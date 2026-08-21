import 'package:flutter/foundation.dart';

import 'controller_server.dart';
import 'storage_service.dart';
import 'vpn_channel.dart';

/// 全局运行状态 (单例).
class AppSession extends ChangeNotifier {
  AppSession._();
  static final AppSession instance = AppSession._();

  /// 当前运行的配置 id, 为空表示未运行.
  String? runningConfigId;

  /// 本地控制通道服务 (跨重启保持).
  ControllerServer? server;

  /// 连接状态: true=avpn 控制通道在线.
  bool connected = false;

  /// 启动时下发的完整配置 json (含 VpnService 专用字段), 用于
  /// update_config 时判断是否需要重建 TUN.
  String? startedConfigJson;

  bool get running => runningConfigId != null;

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
      final server = this.server;
      this.server = null;
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
}
