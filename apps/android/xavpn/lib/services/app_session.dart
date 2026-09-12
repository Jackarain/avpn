import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'launcher_server.dart';
import 'storage_service.dart';
import 'vpn_channel.dart';
import '../models/vpn_config.dart';

/// 全局运行状态 (单例).
class AppSession extends ChangeNotifier {
  AppSession._();
  static final AppSession instance = AppSession._();

  /// 当前运行的配置 id, 为空表示未运行.
  String? runningConfigId;

  /// 本地控制通道服务 (跨重启保持).
  LauncherServer? _server;
  StreamSubscription<bool>? _connSub;

  /// 连接状态: true=avpn 控制通道在线.
  bool connected = false;

  /// 启动时下发的完整配置 json (含 VpnService 专用字段), 用于
  /// update_config 时判断是否需要重建 TUN.
  String? startedConfigJson;

  bool get running => runningConfigId != null;

  /// 当前本地控制通道服务; 未建立时为 null.
  LauncherServer? get server => _server;

  /// 绑定控制通道服务: 连接状态由本类统一订阅, 避免多处重复订阅.
  void attachServer(LauncherServer server) {
    if (identical(_server, server)) return;
    _connSub?.cancel();
    _server = server;
    connected = server.connected;
    _connSub = server.connectionStream.listen(setConnected);
  }

  /// 解绑控制通道服务 (不负责关闭).
  void detachServer() {
    _connSub?.cancel();
    _connSub = null;
    _server = null;
    connected = false;
  }

  /// 等待控制通道连接, 超时返回 false.
  Future<bool> waitForChannel({
    Duration timeout = const Duration(seconds: 5),
  }) {
    final server = _server;
    if (server == null) return Future.value(false);
    if (server.connected) return Future.value(true);
    final completer = Completer<bool>();
    final sub = server.connectionStream.listen((c) {
      if (c && !completer.isCompleted) completer.complete(true);
    });
    return completer.future
        .timeout(timeout, onTimeout: () => false)
        .whenComplete(sub.cancel);
  }

  /// 控制通道未连接时尝试恢复: 必要时重建本地控制端, 再让原生端重连过来.
  /// 返回恢复后是否已连接.
  Future<bool> recoverControlChannel({
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final configJson = startedConfigJson;
    if (configJson == null || configJson.isEmpty) return false;
    var server = _server;
    if (server == null || server.port <= 0) {
      // 本地控制端不可用: 换随机端口重新监听, 再让 avpn 连到新端口.
      final fresh = LauncherServer();
      try {
        await fresh.start();
      } catch (_) {
        return false;
      }
      attachServer(fresh);
      server = fresh;
    }
    try {
      await VpnChannel.restart(configJson, server.port);
    } catch (_) {
      return false;
    }
    if (!await waitForChannel(timeout: timeout)) return false;
    // 端口可能已变化, 更新持久化的运行状态供下次启动恢复.
    final id = runningConfigId;
    if (id != null) await StorageService().saveRunState(id, server.port);
    return true;
  }

  void beginRun(String configId, {String? configJson}) {
    runningConfigId = configId;
    if (configJson != null) startedConfigJson = configJson;
    notifyListeners();
  }

  /// 停止当前运行: 停原生服务、清理持久化运行状态、关闭控制通道.
  Future<void> stopRun() async {
    try {
      await VpnChannel.stop();
    } finally {
      await StorageService().clearRunState();
      final server = _server;
      detachServer();
      try {
        await server?.close();
      } catch (_) {
        // 关闭控制通道失败不影响停止流程.
      }
      endRun();
    }
  }

  void endRun() {
    runningConfigId = null;
    connected = false;
    startedConfigJson = null;
    notifyListeners();
  }

  void setConnected(bool value) {
    if (connected != value) {
      connected = value;
      notifyListeners();
    }
  }

  /// 将配置应用到运行中的会话:
  /// - TUN 字段变更时整体重建 VPN (VpnService 重新 establish);
  /// - 其余参数经控制通道 update_config 热更新.
  /// 返回 'restarted' / 'updated'; 配置未在运行时返回 null.
  Future<String?> applyConfig(VpnConfig config) async {
    if (!running || runningConfigId != config.id) return null;
    final server = this.server;
    if (server == null) throw StateError('控制通道未就绪');

    if (_tunFieldsChanged(config)) {
      final fullJson = jsonEncode(config.toJson());
      await VpnChannel.restart(fullJson, server.port);
      beginRun(config.id, configJson: fullJson);
      await StorageService().saveRunState(config.id, server.port);
      return 'restarted';
    }

    final params = jsonDecode(config.toAvpnJson()) as Map<String, dynamic>;
    final result = await server.call('update_config', params);
    if (result['ok'] != true) {
      throw StateError('update_config 失败: ${result['error']}');
    }
    return result['restarting'] == true ? 'restarted' : 'updated';
  }

  /// TUN 相关字段是否与启动时不同.
  bool _tunFieldsChanged(VpnConfig config) {
    final started = startedConfigJson;
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
}
