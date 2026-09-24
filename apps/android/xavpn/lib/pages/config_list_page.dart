import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

import '../models/vpn_config.dart';
import '../services/app_session.dart';
import '../services/storage_service.dart';
import '../services/vpn_channel.dart';
import '../services/launcher_server.dart';
import '../widgets/update_flow.dart';
import 'config_edit_page.dart';
import 'running_page.dart';

class ConfigListPage extends StatefulWidget {
  const ConfigListPage({super.key});

  @override
  State<ConfigListPage> createState() => _ConfigListPageState();
}

class _ConfigListPageState extends State<ConfigListPage> {
  final StorageService _storage = StorageService();
  List<VpnConfig> _configs = [];
  bool _loading = true;
  bool _busy = false;
  String _gitHash = '';

  /// 启动后延迟检查更新的定时器 (延时是为了不拖慢首屏).
  Timer? _updateTimer;

  @override
  void initState() {
    super.initState();
    AppSession.instance.addListener(_onSession);
    _reload();
    _tryResumeSession();
    // 顶部显示 libxavpn 编译时记录的 git commit hash.
    VpnChannel.buildVersion().then((v) {
      if (mounted && v.isNotEmpty) setState(() => _gitHash = v);
    });
    _updateTimer = Timer(const Duration(seconds: 3), () {
      if (mounted) unawaited(autoCheckUpdate(context));
    });
  }

  /// 界面重建 (Activity 重新打开) 时, 若 VPN 仍在同一进程运行,
  /// 恢复控制通道并标记运行状态. 存活判定基于控制通道 WebSocket 连接
  /// (avpn 重连机制会在数秒内重新连上), 不再使用 JNI status 接口.
  Future<void> _tryResumeSession() async {
    final state = await _storage.loadRunState();
    if (state == null) return;
    final (configId, port) = state;

    final session = AppSession.instance;
    session.beginRun(configId);

    // 同进程内 Activity 重建时可能已有控制通道, 直接复用.
    var server = session.server;
    if (server == null) {
      server = LauncherServer();
      var bound = true;
      try {
        await server.start(port: port);
      } catch (_) {
        // 原端口被占用 (旧控制端尚未释放等): 换随机端口后让原生端重连.
        bound = false;
      }
      session.attachServer(server);
      await _restoreConfigSnapshot(server, configId);
      if (!bound && !await session.recoverControlChannel()) {
        await _abandonResume();
        return;
      }
    } else {
      await _restoreConfigSnapshot(server, configId);
    }

    // 等待 avpn 经控制通道连上; 连不上时尝试拉起一次原生服务.
    if (!await session.waitForChannel() &&
        !await session.recoverControlChannel()) {
      await _abandonResume();
      return;
    }
    if (mounted) setState(() {});
  }

  /// 恢复配置快照: vaddr 下发时据此建立 tun; 控制通道恢复时据此重启原生服务.
  Future<void> _restoreConfigSnapshot(
    LauncherServer server,
    String configId,
  ) async {
    final configs = await _storage.loadConfigs();
    for (final c in configs) {
      if (c.id == configId) {
        final json =
            jsonDecode(jsonEncode(c.toJson())) as Map<String, dynamic>;
        server.setVpnConfig(json);
        AppSession.instance.beginRun(configId, configJson: jsonEncode(json));
        break;
      }
    }
  }

  /// 控制通道无法恢复: 停掉原生服务并清理运行状态, 避免界面停在运行中.
  Future<void> _abandonResume() async {
    final session = AppSession.instance;
    try {
      await VpnChannel.stop();
    } catch (_) {
      // 原生服务可能已退出.
    }
    // 控制通道由 endRun 统一释放.
    await _storage.clearRunState();
    session.endRun();
  }

  @override
  void dispose() {
    _updateTimer?.cancel();
    AppSession.instance.removeListener(_onSession);
    super.dispose();
  }

  void _onSession() {
    if (mounted) setState(() {});
  }

  Future<void> _reload() async {
    final list = await _storage.loadConfigs();
    if (!mounted) return;
    setState(() {
      _configs = list;
      _loading = false;
    });
  }

  Future<void> _save() => _storage.saveConfigs(_configs);

  Future<void> _runConfig(VpnConfig config) async {
    if (_busy) return;
    if (AppSession.instance.running) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('请先停止当前连接')));
      }
      return;
    }
    setState(() => _busy = true);
    final session = AppSession.instance;
    var createdServer = false;
    try {
      final ok = await VpnChannel.prepare();
      if (!ok) {
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(const SnackBar(content: Text('未获得 VPN 授权')));
        }
        return;
      }

      // 总是新建控制通道 server: 不复用 session.server, 避免快速启停时
      // 复用到上一轮已关闭/正在关闭的旧实例(旧端口已无监听/内部状态
      // 残留), 导致 avpn 连不上控制通道, 界面永远等待连接.
      final oldServer = session.server;
      if (oldServer != null) {
        session.detachServer();
        unawaited(oldServer.close());
      }
      final server = LauncherServer();
      await server.start();
      session.attachServer(server);
      createdServer = true;

      final fullJson = jsonEncode(config.toJson());
      // 设置 vpnConfig 快照: 握手后 vaddr 下发时据此建立 VpnService tun.
      server.setVpnConfig(config.toJson());
      await VpnChannel.start(fullJson, server.port);
      session.beginRun(config.id, configJson: fullJson);
      await _storage.saveRunState(config.id, server.port);
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => RunningPage(configId: config.id)),
      );
      if (mounted) setState(() {});
    } catch (e) {
      // 启动失败: 若本次新建了控制通道且未进入运行态, 关闭释放,
      // 避免陈旧 server 残留(占用端口/状态) 被下次启动复用.
      if (createdServer && !session.running) {
        final server = session.server;
        if (server != null) {
          session.detachServer();
          unawaited(server.close());
        }
      }
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('启动失败: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _stopAll() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await AppSession.instance.stopRun();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('停止失败: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _addConfig() async {
    final config = VpnConfig(id: VpnConfig.newId(), name: '新配置');
    final saved = await Navigator.of(context).push<VpnConfig>(
      MaterialPageRoute(
        builder: (_) => ConfigEditPage(config: config, isNew: true),
      ),
    );
    if (saved != null) {
      _configs.add(saved);
      await _save();
      _reload();
    }
  }

  Future<void> _editConfig(VpnConfig config) async {
    final saved = await Navigator.of(context).push<VpnConfig>(
      MaterialPageRoute(
        builder: (_) => ConfigEditPage(config: config.copy(), isNew: false),
      ),
    );
    if (saved != null) {
      final i = _configs.indexWhere((c) => c.id == saved.id);
      if (i >= 0) _configs[i] = saved;
      await _save();
      _reload();
      // 保存后自动应用到运行中的会话, 无需再手动点击应用.
      if (AppSession.instance.runningConfigId == saved.id) {
        try {
          final applied = await AppSession.instance.applyConfig(saved);
          if (mounted && applied != null) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(
                  applied == 'restarted' ? '配置已保存, VPN 已重建' : '配置已保存并热更新',
                ),
              ),
            );
          }
        } catch (e) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('保存成功, 但应用失败: $e')),
            );
          }
        }
      }
    }
  }

  Future<void> _deleteConfig(VpnConfig config) async {
    if (AppSession.instance.runningConfigId == config.id) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('请先停止当前连接再删除')));
      }
      return;
    }
    final confirmed =
        await showDialog<bool>(
          context: context,
          builder:
              (ctx) => AlertDialog(
                title: const Text('删除配置'),
                content: Text('确定删除「${config.name}」吗?'),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.of(ctx).pop(false),
                    child: const Text('取消'),
                  ),
                  FilledButton(
                    onPressed: () => Navigator.of(ctx).pop(true),
                    child: const Text('删除'),
                  ),
                ],
              ),
        ) ??
        false;
    if (!confirmed) return;
    _configs.removeWhere((c) => c.id == config.id);
    await _save();
    _reload();
  }

  Future<void> _duplicateConfig(VpnConfig config) async {
    final copy =
        config.copy()
          ..id = VpnConfig.newId()
          ..name = '${config.name} 副本';
    _configs.add(copy);
    await _save();
    _reload();
  }

  @override
  Widget build(BuildContext context) {
    final session = AppSession.instance;
    return Scaffold(
      appBar: AppBar(
        title: const Text('aVPN 配置'),
        actions: [
          IconButton(
            tooltip: '检查更新',
            onPressed: _busy ? null : () => unawaited(checkUpdateNow(context)),
            icon: const Icon(Icons.system_update_alt),
          ),
          if (_gitHash.isNotEmpty)
            Center(
              child: Padding(
                padding: const EdgeInsets.only(right: 8),
                child: Text(
                  _gitHash,
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          if (session.running) ...[
            IconButton(
              tooltip: '运行控制台',
              onPressed:
                  _busy
                      ? null
                      : () {
                        final id = session.runningConfigId;
                        if (id != null) {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => RunningPage(configId: id),
                            ),
                          );
                        }
                      },
              icon: const Icon(Icons.monitor_heart_outlined),
            ),
            TextButton.icon(
              onPressed: _busy ? null : _stopAll,
              icon: const Icon(Icons.stop_circle_outlined),
              label: const Text('停止'),
            ),
          ],
        ],
      ),
      body:
          _loading
              ? const Center(child: CircularProgressIndicator())
              : _configs.isEmpty
              ? const Center(child: Text('暂无配置, 点击右下角添加'))
              : RefreshIndicator(
                onRefresh: _reload,
                child: ListView.separated(
                  padding: const EdgeInsets.all(12),
                  itemCount: _configs.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (context, i) {
                    final config = _configs[i];
                    final running = session.runningConfigId == config.id;
                    return Card(
                      child: ListTile(
                        leading: CircleAvatar(
                          child: Icon(
                            config.mode == 'gateway'
                                ? Icons.hub_outlined
                                : Icons.vpn_key_outlined,
                          ),
                        ),
                        title: Row(
                          children: [
                            Expanded(
                              child: Text(
                                config.name,
                                style: const TextStyle(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                            if (running)
                              const Chip(
                                label: Text('运行中'),
                                visualDensity: VisualDensity.compact,
                                backgroundColor: Colors.green,
                                labelStyle: TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                ),
                              ),
                          ],
                        ),
                        subtitle: Text(
                          _subtitle(config),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              tooltip: running ? '正在运行' : '运行此配置',
                              onPressed:
                                  running ? null : () => _runConfig(config),
                              icon: Icon(
                                running
                                    ? Icons.play_circle_filled
                                    : Icons.play_circle_outline,
                                color: running ? Colors.green : null,
                              ),
                            ),
                            PopupMenuButton<String>(
                              onSelected: (action) {
                                switch (action) {
                                  case 'edit':
                                    _editConfig(config);
                                  case 'duplicate':
                                    _duplicateConfig(config);
                                  case 'delete':
                                    _deleteConfig(config);
                                }
                              },
                              itemBuilder:
                                  (_) => const [
                                    PopupMenuItem(
                                      value: 'edit',
                                      child: Text('编辑'),
                                    ),
                                    PopupMenuItem(
                                      value: 'duplicate',
                                      child: Text('复制'),
                                    ),
                                    PopupMenuItem(
                                      value: 'delete',
                                      child: Text('删除'),
                                    ),
                                  ],
                            ),
                          ],
                        ),
                        onTap:
                            () =>
                                running
                                    ? Navigator.of(context).push(
                                      MaterialPageRoute(
                                        builder:
                                            (_) => RunningPage(
                                              configId: config.id,
                                            ),
                                      ),
                                    )
                                    : _editConfig(config),
                      ),
                    );
                  },
                ),
              ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _busy ? null : _addConfig,
        icon: const Icon(Icons.add),
        label: const Text('添加配置'),
      ),
      bottomNavigationBar: _busy ? const LinearProgressIndicator() : null,
    );
  }

  String _subtitle(VpnConfig config) {
    final b = StringBuffer();
    if (config.mode == 'gateway') {
      final listens = [...config.udpListen, ...config.tcpListen];
      b.write('网关: ${listens.isEmpty ? '未配置监听' : listens.join(', ')}');
    } else {
      b.write(
        '客户端: ${config.nexthop.isEmpty ? '未配置 nexthop' : config.nexthop}',
      );
    }
    final mtu = config.mtuSize > 0 ? ', MTU ${config.mtuSize}' : '';
    b.write(mtu);
    return b.toString();
  }
}
