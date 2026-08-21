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
  static Future<void> start(String configJson, int controllerPort) async {
    final ok = await _channel.invokeMethod<bool>('start', {
      'config': configJson,
      'controllerPort': controllerPort,
    });
    if (ok != true) {
      throw StateError('native start failed');
    }
  }

  /// 停止 VpnService 并调用 xavpn.stop().
  static Future<void> stop() async {
    await _channel.invokeMethod('stop');
  }

  /// 不停服务重建 VPN (TUN 参数变更): 原生端在单个任务内 停旧->启新.
  static Future<void> restart(String configJson, int controllerPort) async {
    final ok = await _channel.invokeMethod<bool>('restart', {
      'config': configJson,
      'controllerPort': controllerPort,
    });
    if (ok != true) {
      throw StateError('native restart failed');
    }
  }

  static Future<String> status() async {
    return (await _channel.invokeMethod<String>('status')) ?? '{}';
  }

  /// 原生事件: {"type":"log"|"vpn_state", ...}.
  static Stream<Map<String, dynamic>> events() {
    return _events.receiveBroadcastStream().map(
      (e) => Map<String, dynamic>.from(e as Map),
    );
  }
}
