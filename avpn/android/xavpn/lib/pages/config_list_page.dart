import 'dart:convert';

import 'package:flutter/material.dart';

import '../models/vpn_config.dart';
import '../services/app_session.dart';
import '../services/storage_service.dart';
import '../services/vpn_channel.dart';
import '../services/controller_server.dart';
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

  @override
  void initState() {
    super.initState();
    AppSession.instance.addListener(_onSession);
    _reload();
    _tryResumeSession();
  }

  /// 界面重建 (Activity 重新打开) 时, 若 VPN 仍在同一进程运行,
  /// 恢复控制通道并标记运行状态.
  Future<void> _tryResumeSession() async {
    final state = await _storage.loadRunState();
    if (state == null) return;
    final (configId, port) = state;

    final alive = await _nativeAlive();
    if (!alive) {
      await _storage.clearRunState();
      return;
    }

    final session = AppSession.instance;
    session.beginRun(configId);
    // 同进程内 Activity 重建时可能已有控制通道, 直接复用.
    var server = session.server;
    if (server == null) {
      try {
        server = ControllerServer();
        await server.start(port: port);
        session.server = server;
      } catch (_) {
        // 原端口被占用等情况下控制通道暂不可用, 不影响 VPN 本身运行.
        if (mounted) setState(() {});
        return;
      }
    }
    server.connectionStream.listen((c) => session.setConnected(c));
    if (mounted) setState(() {});
  }

  /// native 服务是否仍在运行 (status json 含 mode 字段).
  Future<bool> _nativeAlive() async {
    try {
      final json = await VpnChannel.status();
      final map = jsonDecode(json) as Map<String, dynamic>;
      return map.containsKey('mode');
    } catch (_) {
      return false;
    }
  }

  @override
  void dispose() {
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

      final session = AppSession.instance;
      var server = session.server;
      if (server == null) {
        server = ControllerServer();
        await server.start();
        session.server = server;
      }
      server.connectionStream.listen((c) => session.setConnected(c));

      final fullJson = jsonEncode(config.toJson());
      await VpnChannel.start(fullJson, server.port);
      session.beginRun(config.id, configJson: fullJson);
      await _storage.saveRunState(config.id, server.port);
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => RunningPage(configId: config.id)),
      );
      if (mounted) setState(() {});
    } catch (e) {
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
