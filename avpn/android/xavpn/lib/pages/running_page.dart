import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/vpn_config.dart';
import '../services/app_session.dart';
import '../services/controller_server.dart';
import '../services/storage_service.dart';
import '../services/vpn_channel.dart';

class RunningPage extends StatefulWidget {
  const RunningPage({super.key, required this.configId});

  final String configId;

  @override
  State<RunningPage> createState() => _RunningPageState();
}

class _RunningPageState extends State<RunningPage>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 2, vsync: this);
  final StorageService _storage = StorageService();
  final List<Map<String, dynamic>> _logs = [];
  String _stateMessage = '';
  Map<String, dynamic>? _status;
  bool _busy = false;
  bool _connected = false;
  StreamSubscription<Map<String, dynamic>>? _statusSub;
  StreamSubscription<Map<String, dynamic>>? _logSub;
  StreamSubscription<bool>? _connSub;
  StreamSubscription<Map<String, dynamic>>? _nativeEventsSub;

  ControllerServer? get _server => AppSession.instance.server;

  @override
  void initState() {
    super.initState();
    final server = _server;
    if (server != null) {
      _connSub = server.connectionStream.listen((c) {
        if (mounted) setState(() => _connected = c);
      });
      _statusSub = server.statusStream.listen((s) {
        if (mounted) setState(() => _status = s);
      });
      _logSub = server.logStream.listen(_onLog);
    }
    // 事件通道 (native vpn_state / JNI 日志兜底).
    _nativeEventsSub = VpnChannel.events().listen((e) {
      if (e['type'] == 'log') {
        if (mounted) {
          setState(() {
            _addLog({
              'time': e['time'] ?? 0,
              'level': e['level'] ?? 1,
              'message': e['message'] ?? '',
            });
          });
        }
      } else if (e['type'] == 'vpn_state') {
        final state = e['state'] as String? ?? '';
        if (state == 'error') {
          // native 启动失败/异常退出: 清理运行状态, 界面提示.
          _storage.clearRunState();
          AppSession.instance.endRun();
        }
        if (mounted) {
          setState(() {
            _stateMessage = e['message'] as String? ?? '';
          });
        }
      }
    }, onError: (Object _) {
      // 引擎分离等场景下事件流中断, 状态仍由 WS 控制通道维持.
    });
    _connected = server?.connected ?? false;
  }

  static const int _maxLogLines = 500;

  void _addLog(Map<String, dynamic> entry) {
    _logs.add(entry);
    if (_logs.length > _maxLogLines) {
      _logs.removeRange(0, _logs.length - _maxLogLines);
    }
  }

  void _onLog(Map<String, dynamic> log) {
    final lines = log['lines'];
    if (lines is List && lines.isNotEmpty) {
      setState(() {
        for (final line in lines) {
          if (line is Map) {
            _addLog(Map<String, dynamic>.from(line));
          }
        }
      });
    }
  }

  @override
  void dispose() {
    _statusSub?.cancel();
    _logSub?.cancel();
    _connSub?.cancel();
    _nativeEventsSub?.cancel();
    _tabs.dispose();
    super.dispose();
  }

  Future<VpnConfig?> _currentConfig() async {
    final list = await _storage.loadConfigs();
    for (final c in list) {
      if (c.id == widget.configId) return c;
    }
    return null;
  }

  /// 通过 controller ws 协议动态更新参数, 返回原生响应.
  Future<Map<String, dynamic>> _applyUpdate(Map<String, dynamic> params) async {
    final server = _server;
    if (server == null) throw StateError('控制通道未就绪');
    final result = await server.call('update_config', params);
    if (result['ok'] != true) {
      throw StateError('update_config 失败: ${result['error']}');
    }
    return result;
  }

  Future<void> _applyFullConfig() async {
    final config = await _currentConfig();
    if (config == null) return;
    setState(() => _busy = true);
    try {
      // TUN 地址/路由/DNS/MTU 由 VpnService 建立, 变更时直接整体重建 VPN.
      if (_tunFieldsChanged(config)) {
        await _restartWithConfig(config);
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(const SnackBar(content: Text('TUN 参数已变更, VPN 已重建')));
        }
        return;
      }

      final params = jsonDecode(config.toAvpnJson()) as Map<String, dynamic>;
      final result = await _applyUpdate(params);
      if (mounted) {
        final restarting = result['restarting'] == true;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(restarting ? '配置已下发, 服务自动重启生效' : '配置已热更新生效')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('应用失败: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// TUN 相关字段是否与启动时不同.
  bool _tunFieldsChanged(VpnConfig config) {
    final started = AppSession.instance.startedConfigJson;
    if (started == null || started.isEmpty) return false;
    try {
      final old = VpnConfig.fromJson(
        jsonDecode(started) as Map<String, dynamic>,
      );
      return old.tunAddress != config.tunAddress ||
          old.tunPrefix != config.tunPrefix ||
          old.routes.join(',') != config.routes.join(',') ||
          old.dns.join(',') != config.dns.join(',') ||
          old.mtuSize != config.mtuSize;
    } catch (_) {
      return false;
    }
  }

  /// 停止并重新建立 VPN (VpnService 重建 TUN, 控制通道保持).
  Future<void> _restartWithConfig(VpnConfig config) async {
    final server = AppSession.instance.server;
    if (server == null) throw StateError('控制通道未就绪');
    final fullJson = jsonEncode(config.toJson());
    await VpnChannel.restart(fullJson, server.port);
    AppSession.instance.beginRun(config.id, configJson: fullJson);
    await _storage.saveRunState(config.id, server.port);
  }

  Future<void> _stop() async {
    setState(() => _busy = true);
    try {
      await AppSession.instance.stopRun();
      _stateMessage = '';
      if (mounted) Navigator.of(context).pop();
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('运行控制台'),
        actions: [
          IconButton(
            onPressed: _logs.isEmpty ? null : _copyAllLogs,
            icon: const Icon(Icons.copy_all),
            tooltip: '复制全部日志',
          ),
          IconButton(
            onPressed: _logs.isEmpty ? null : _clearLogs,
            icon: const Icon(Icons.delete_sweep),
            tooltip: '清空日志',
          ),
          TextButton.icon(
            onPressed: _busy ? null : _stop,
            icon: const Icon(Icons.stop),
            label: const Text('停止'),
          ),
        ],
      ),
      body: Column(
        children: [
          _statusBanner(context),
          TabBar(
            controller: _tabs,
            tabs: const [Tab(text: '状态'), Tab(text: '日志')],
          ),
          Expanded(
            child: TabBarView(
              controller: _tabs,
              children: [_buildStatusTab(context), _buildLogTab()],
            ),
          ),
        ],
      ),
    );
  }

  Widget _statusBanner(BuildContext context) {
    final running = AppSession.instance.running;
    final Color color;
    final String text;
    if (!running) {
      color = Colors.orange;
      text = '未运行';
    } else if (_connected) {
      color = Colors.green;
      text = '控制通道已连接';
    } else {
      color = Colors.orange;
      text = '等待 avpn 连接控制通道...';
    }
    if (_stateMessage.isNotEmpty) {
      return Container(
        width: double.infinity,
        color: color,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        child: Text(_stateMessage, style: const TextStyle(color: Colors.white)),
      );
    }
    return Container(
      width: double.infinity,
      color: color,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: Row(
        children: [
          Icon(Icons.circle, size: 10, color: Colors.white),
          const SizedBox(width: 8),
          Text(text, style: const TextStyle(color: Colors.white)),
        ],
      ),
    );
  }

  Widget _buildStatusTab(BuildContext context) {
    final s = _status ?? const {};
    final rates = s['rates'] as Map<String, dynamic>? ?? const {};
    final global = s['global'] as Map<String, dynamic>? ?? const {};
    final sessions = s['sessions'] as List<dynamic>? ?? const [];
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          children: [
            Expanded(child: _statCard('上传速率', _fmtRate(rates['rx_rate_bps']))),
            const SizedBox(width: 12),
            Expanded(child: _statCard('下载速率', _fmtRate(rates['tx_rate_bps']))),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(child: _statCard('上行流量', _fmtBytes(global['rx_bytes']))),
            const SizedBox(width: 12),
            Expanded(child: _statCard('下行流量', _fmtBytes(global['tx_bytes']))),
          ],
        ),
        const SizedBox(height: 12),
        _infoTile('模式', s['mode'] as String? ?? '-'),
        _infoTile('运行时长', _fmtUptime(s['uptime'])),
        _infoTile('活动连接', '${s['active_connections'] ?? 0}'),
        if (s['started_at'] is int)
          _infoTile('启动时间', _fmtTime(s['started_at'])),
        if (sessions.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text('会话', style: Theme.of(context).textTheme.titleSmall),
          for (final item in sessions)
            if (item is Map<String, dynamic>)
              Card(
                child: ListTile(
                  dense: true,
                  title: Text(
                    '${item['vaddr'] ?? '-'}  ${item['transport'] ?? 'udp'}',
                  ),
                  subtitle: Text(
                    'remote: ${item['remote'] ?? '-'}\n'
                    'up ${_fmtBytes(item['rx_bytes'])} '
                    'down ${_fmtBytes(item['tx_bytes'])} '
                    '(${_fmtRate(item['rx_rate_bps'])} / ${_fmtRate(item['tx_rate_bps'])})',
                  ),
                  isThreeLine: true,
                ),
              ),
        ],
        const SizedBox(height: 24),
        FilledButton.icon(
          onPressed: _busy ? null : _applyFullConfig,
          icon: const Icon(Icons.sync),
          label: const Text('应用当前配置 (update_config)'),
        ),
      ],
    );
  }

  Widget _buildLogTab() {
    if (_logs.isEmpty) {
      return const Center(child: Text('暂无日志'));
    }
    return ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _logs.length,
      itemBuilder: (context, i) {
        final log = _logs[i];
        final level = log['level'] as int? ?? 1;
        final message = log['message'] as String? ?? '';
        final time = log['time'] as int? ?? 0;
        final color = switch (level) {
          0 => Colors.grey,
          2 => Colors.orange,
          3 => Colors.red,
          _ => Theme.of(context).colorScheme.onSurface,
        };
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: SelectableText(
            '[${_fmtTimeMs(time)}] $message',
            style: TextStyle(fontSize: 12, color: color),
          ),
        );
      },
    );
  }

  void _clearLogs() {
    setState(() => _logs.clear());
  }

  Future<void> _copyAllLogs() async {
    final text = _logs
        .map((log) => '[${_fmtTimeMs(log['time'] as int? ?? 0)}] '
            '${log['message'] as String? ?? ''}')
        .join('\n');
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('已复制全部日志到剪贴板')),
    );
  }

  Widget _statCard(String label, String value) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 4),
            Text(
              value,
              style: Theme.of(
                context,
              ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoTile(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          SizedBox(
            width: 90,
            child: Text(label, style: Theme.of(context).textTheme.bodySmall),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }

  String _fmtRate(Object? v) {
    final n = v is num ? v.toDouble() : 0.0;
    if (n >= 1024 * 1024) return '${(n / 1024 / 1024).toStringAsFixed(2)} MB/s';
    if (n >= 1024) return '${(n / 1024).toStringAsFixed(1)} KB/s';
    return '${n.toStringAsFixed(0)} B/s';
  }

  String _fmtBytes(Object? v) {
    final n = v is num ? v.toDouble() : 0.0;
    if (n >= 1024 * 1024 * 1024) {
      return '${(n / 1024 / 1024 / 1024).toStringAsFixed(2)} GB';
    }
    if (n >= 1024 * 1024) return '${(n / 1024 / 1024).toStringAsFixed(1)} MB';
    if (n >= 1024) return '${(n / 1024).toStringAsFixed(0)} KB';
    return '${n.toStringAsFixed(0)} B';
  }

  String _fmtUptime(Object? v) {
    final n = v is int ? v : 0;
    final h = n ~/ 3600;
    final m = (n % 3600) ~/ 60;
    final s = n % 60;
    return '${h.toString().padLeft(2, '0')}:${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  String _fmtTime(Object? v) {
    if (v is! int) return '-';
    final t = DateTime.fromMillisecondsSinceEpoch(v * 1000);
    return '${t.toLocal()}';
  }

  String _fmtTimeMs(int ms) {
    if (ms <= 0) return '--:--:--';
    final t = DateTime.fromMillisecondsSinceEpoch(ms);
    final h = t.hour.toString().padLeft(2, '0');
    final m = t.minute.toString().padLeft(2, '0');
    final s = t.second.toString().padLeft(2, '0');
    return '$h:$m:$s';
  }
}
