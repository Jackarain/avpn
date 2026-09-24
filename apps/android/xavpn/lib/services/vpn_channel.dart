import 'dart:async';

import 'package:flutter/services.dart';

/// Flutter 与 Android 原生层 (VpnService/JNI 桥) 的通道.
class VpnChannel {
  static const MethodChannel _channel = MethodChannel(
    'com.jackarain.xavpn/vpn',
  );
  static const EventChannel _events = EventChannel(
    'com.jackarain.xavpn/events',
  );

  /// 请求 VPN 授权 (阻塞直到用户在系统弹窗中作出选择).
  static Future<bool> prepare() async {
    final ok = await _channel.invokeMethod<bool>('prepare');
    return ok ?? false;
  }

  /// 启动 VpnService 并调用 xavpn.start(configJson).
  static Future<void> start(String configJson, int launcherPort) async {
    final ok = await _channel.invokeMethod<bool>('start', {
      'config': configJson,
      'launcherPort': launcherPort,
    });
    if (ok != true) {
      throw StateError('native start failed');
    }
  }

  /// 停止 VpnService 并调用 xavpn.stop().
  ///
  /// native 端在服务实例完全销毁 (onDestroy) 后才完成该调用, 使 Flutter
  /// 的停止流程与服务的真实生命周期同步: 否则下一次 connect 的 START 可能
  /// 提交到正在销毁的旧实例, 导致 VpnService 未运行、establish_tun 失败
  /// (TUN 创建失败无法使用). 带超时保护, 防止服务销毁异常时永久阻塞.
  static Future<void> stop() async {
    await _channel
        .invokeMethod('stop')
        .timeout(const Duration(seconds: 8), onTimeout: () => null);
  }

  /// 返回 libxavpn 编译时记录的 git commit hash 前 6 位.
  static Future<String> buildVersion() async {
    final v = await _channel.invokeMethod<String>('build_version');
    return v ?? '';
  }

  /// 不停服务重建 VPN (TUN 参数变更): 原生端在单个任务内 停旧->启新.
  static Future<void> restart(String configJson, int launcherPort) async {
    final ok = await _channel.invokeMethod<bool>('restart', {
      'config': configJson,
      'launcherPort': launcherPort,
    });
    if (ok != true) {
      throw StateError('native restart failed');
    }
  }

  /// 放行原生对外 socket (经控制通道 protect 请求触发).
  static Future<bool> protect(int fd) async {
    final ok = await _channel.invokeMethod<bool>('protect', {'fd': fd});
    return ok ?? false;
  }

  /// 以服务端下发的 vaddr 建立 VpnService tun, 返回注入 libavpn 的 fd.
  static Future<int> establishTun({
    required String address,
    required int prefix,
    required int mtu,
    required List<String> routes,
    required List<String> dns,
    required String session,
  }) async {
    final fd = await _channel.invokeMethod<int>('establish_tun', {
      'address': address,
      'prefix': prefix,
      'mtu': mtu,
      'routes': routes,
      'dns': dns,
      'session': session,
    });
    if (fd == null || fd < 0) {
      throw StateError('establish_tun 失败');
    }
    return fd;
  }

  /// 关闭未成功注入 libavpn 的 tun fd.
  ///
  /// 注入失败或被停止流程中断时 fd 未被 native 接管, 必须关闭, 否则
  /// VpnService tun 设备残留, 影响后续建立.
  static Future<void> closeTunFd(int fd) async {
    await _channel.invokeMethod('close_tun_fd', {'fd': fd});
  }

  /// 原生事件: {"type":"log"|"vpn_state", ...}.
  static Stream<Map<String, dynamic>> events() {
    return _events.receiveBroadcastStream().map(
      (e) => Map<String, dynamic>.from(e as Map),
    );
  }
}
