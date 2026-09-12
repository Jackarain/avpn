import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xavpn/services/app_session.dart';
import 'package:xavpn/services/launcher_server.dart';

void main() {
  final session = AppSession.instance;

  tearDown(() async {
    final server = session.server;
    session.detachServer();
    await server?.close();
    session.endRun();
  });

  test('绑定控制端后连接状态随 WebSocket 变化', () async {
    final server = LauncherServer();
    await server.start();
    session.attachServer(server);

    expect(session.server, same(server));
    expect(session.connected, isFalse);

    final ws = await WebSocket.connect('ws://127.0.0.1:${server.port}');
    await _settle();
    expect(session.connected, isTrue);

    await ws.close();
    await _settle();
    expect(session.connected, isFalse);
  });

  test('无控制端时等待连接超时返回 false', () async {
    expect(
      await session.waitForChannel(timeout: const Duration(milliseconds: 50)),
      isFalse,
    );
  });

  test('控制端连上后等待连接返回 true', () async {
    final server = LauncherServer();
    await server.start();
    session.attachServer(server);

    final wait = session.waitForChannel(timeout: const Duration(seconds: 2));
    final ws = await WebSocket.connect('ws://127.0.0.1:${server.port}');
    expect(await wait, isTrue);
    await ws.close();
  });

  test('缺少启动配置时恢复控制通道直接失败', () async {
    final server = LauncherServer();
    await server.start();
    session.attachServer(server);

    expect(
      await session.recoverControlChannel(timeout: const Duration(seconds: 1)),
      isFalse,
    );
  });
}

/// 等待事件循环处理 WebSocket 连接状态变化.
Future<void> _settle() => Future<void>.delayed(const Duration(milliseconds: 100));
