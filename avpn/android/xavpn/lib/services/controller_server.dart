import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'cn_ip_list.dart';
import 'vpn_channel.dart';

/// 本地 JSON-RPC over WebSocket 控制服务端.
///
/// 作为 libavpn controller 的控制端: avpn 启动后会主动连接
/// ws://127.0.0.1:port, 注册实例并持续上报 status/log/vaddr;
/// 本端可向其发起 get_status / update_config / set_tun_fd / shutdown 等
/// RPC 请求, 并响应 avpn 的 protect 请求 (放行对外 socket).
class ControllerServer {
  HttpServer? _server;
  WebSocket? _socket;
  int _nextId = 1;
  final Map<int, Completer<Map<String, dynamic>>> _pending = {};
  // 流控制器随 start() 创建; close() 后实例不可再用, 需新建.
  late StreamController<Map<String, dynamic>> _statusCtrl;
  late StreamController<Map<String, dynamic>> _logCtrl;
  late StreamController<Map<String, dynamic>> _registerCtrl;
  late StreamController<bool> _connCtrl;
  bool _started = false;
  bool _closed = false;

  /// 监听端口 (start 后有效).
  int get port => _server?.port ?? 0;

  /// 启动时的 VpnConfig.toJson 快照 (vaddr 下发后建立 tun 用).
  Map<String, dynamic>? _vpnConfig;

  /// 设置 VPN 配置快照, vaddr 通知时据此建立 tun (路由/DNS/会话名).
  void setVpnConfig(Map<String, dynamic> config) => _vpnConfig = config;

  /// 是否已连接 (avpn 控制通道在线).
  bool get connected => _socket != null;

  /// avpn 上报的状态 (status 通知).
  Stream<Map<String, dynamic>> get statusStream => _statusCtrl.stream;

  /// avpn 上报的日志 (log 通知).
  Stream<Map<String, dynamic>> get logStream => _logCtrl.stream;

  /// avpn 实例注册信息 (register 通知).
  Stream<Map<String, dynamic>> get registerStream => _registerCtrl.stream;

  /// 连接状态变化 (true=已连接).
  Stream<bool> get connectionStream => _connCtrl.stream;

  /// 启动本地控制端. [port] 用于进程重启后恢复原端口以便 avpn 重连;
  /// 绑定失败时抛出异常 (调用方决定是否回退).
  Future<void> start({int? port}) async {
    if (_closed) throw StateError('controller 已关闭, 请创建新实例');
    if (_server != null) throw StateError('controller 已启动');
    _statusCtrl = StreamController<Map<String, dynamic>>.broadcast();
    _logCtrl = StreamController<Map<String, dynamic>>.broadcast();
    _registerCtrl = StreamController<Map<String, dynamic>>.broadcast();
    _connCtrl = StreamController<bool>.broadcast();
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, port ?? 0);
    _server!.listen(_handleRequest, onError: (_) {});
    _started = true;
  }

  Future<void> _handleRequest(HttpRequest request) async {
    if (WebSocketTransformer.isUpgradeRequest(request)) {
      try {
        final ws = await WebSocketTransformer.upgrade(request);
        _socket?.close();
        _socket = ws;
        _connCtrl.add(true);
        ws.listen(
          _onMessage,
          onDone: () {
            if (identical(_socket, ws)) {
              _socket = null;
              _connCtrl.add(false);
            }
          },
          onError: (_) {
            if (identical(_socket, ws)) {
              _socket = null;
              _connCtrl.add(false);
            }
          },
          cancelOnError: true,
        );
      } catch (_) {
        // 升级失败, 忽略.
      }
    } else {
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
    }
  }

  void _replyError(Object? id, int code, String message) {
    final ws = _socket;
    if (ws == null) return;
    try {
      ws.add(
        utf8.encode(
          jsonEncode({
            'jsonrpc': '2.0',
            'id': id,
            'error': {'code': code, 'message': message},
          }),
        ),
      );
    } catch (_) {}
  }

  /// 回复 avpn 的请求.
  void _reply(Object? id, Map<String, dynamic> result) {
    final ws = _socket;
    if (ws == null) return;
    try {
      ws.add(
        utf8.encode(
          jsonEncode({
            'jsonrpc': '2.0',
            'id': id,
            'result': result,
          }),
        ),
      );
    } catch (_) {}
  }

  /// 处理 avpn -> app 请求.
  Future<void> _handleWsRequest(
    String method,
    Map<String, dynamic> params,
    Object? id,
  ) async {
    try {
      switch (method) {
        case 'protect':
          // 放行 libavpn 对外 socket, 避免流量回环进 tun.
          final fd = (params['fd'] as num?)?.toInt() ?? -1;
          _reply(id, {'ok': await VpnChannel.protect(fd)});
        default:
          _replyError(id, -32601, 'method not found');
      }
    } catch (e) {
      _replyError(id, -32602, e.toString());
    }
  }

  /// 处理 vaddr 通知: 用服务端下发的地址建立 tun, 再注入 libavpn.
  Future<void> _handleVaddr(Map<String, dynamic> params) async {
    final address = params['ip'] as String? ?? '';
    final prefix = (params['prefix'] as num?)?.toInt() ?? 24;
    final mtu = (params['mtu'] as num?)?.toInt() ?? 1450;
    if (address.isEmpty) return;
    final cfg = _vpnConfig ?? const <String, dynamic>{};
    List<String> routes;
    if (cfg['bypassCn'] == true) {
      // 绕过中国大陆: 仅非中国段接入 VPN, 中国段走系统物理网络直连.
      final cn = await CnIpList.update();
      routes = CnIpList.vpnRoutes(cn);
      if (routes.isEmpty) {
        // 无缓存且拉取失败时回退用户配置路由.
        routes = _strList(cfg['routes']);
      }
    } else {
      routes = _strList(cfg['routes']);
    }
    try {
      final fd = await VpnChannel.establishTun(
        address: address,
        prefix: prefix,
        mtu: mtu,
        routes: routes,
        dns: _strList(cfg['dns']),
        session: cfg['name'] as String? ?? 'aVPN',
      );
      final result = await call('set_tun_fd', {'ptun_fd': fd});
      if (result['ok'] != true) {
        _logLocal('set_tun_fd 失败: ${result['error']}');
      }
    } catch (e) {
      _logLocal('建立 TUN 失败: $e');
    }
  }

  void _logLocal(String message) {
    try {
      _logCtrl.add({
        'lines': [
          {
            'time': DateTime.now().millisecondsSinceEpoch,
            'level': 3,
            'message': message,
          },
        ],
      });
    } catch (_) {}
  }

  static List<String> _strList(dynamic v) {
    if (v is List) return v.whereType<String>().toList();
    return const [];
  }

  void _onMessage(dynamic data) {
    String text;
    if (data is List<int>) {
      text = utf8.decode(data);
    } else if (data is String) {
      text = data;
    } else {
      return;
    }

    Map<String, dynamic> msg;
    try {
      msg = jsonDecode(text) as Map<String, dynamic>;
    } catch (_) {
      return;
    }

    if (msg.containsKey('method')) {
      final method = msg['method'] as String? ?? '';
      final params = msg['params'] as Map<String, dynamic>? ?? const {};
      if (msg.containsKey('id')) {
        // avpn -> app 请求 (如 protect), 异步处理并回复.
        unawaited(_handleWsRequest(method, params, msg['id']));
        return;
      }
      // avpn -> app 通知.
      switch (method) {
        case 'status':
          _statusCtrl.add(params);
        case 'log':
          _logCtrl.add(params);
        case 'register':
          _registerCtrl.add(params);
        case 'vaddr':
          // 服务端下发的 tun 地址: 建立 VpnService tun 并注入 libavpn.
          unawaited(_handleVaddr(params));
      }
    } else if (msg.containsKey('id')) {
      // 本端 RPC 请求的响应.
      final id = (msg['id'] as num?)?.toInt();
      if (id == null) return;
      final completer = _pending.remove(id);
      if (completer == null) return;
      if (msg.containsKey('result')) {
        completer.complete(msg['result'] as Map<String, dynamic>? ?? const {});
      } else {
        completer.completeError(
          StateError('rpc error: ${jsonEncode(msg['error'])}'),
        );
      }
    }
  }

  /// 向 avpn 发起一次 JSON-RPC 请求并等待响应.
  Future<Map<String, dynamic>> call(
    String method,
    Map<String, dynamic> params, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final ws = _socket;
    if (ws == null) throw StateError('controller 未连接');
    final id = _nextId++;
    final completer = Completer<Map<String, dynamic>>();
    _pending[id] = completer;
    // 与原生端 ws binary(true) 对齐, 发送二进制帧.
    ws.add(
      utf8.encode(
        jsonEncode({
          'jsonrpc': '2.0',
          'id': id,
          'method': method,
          'params': params,
        }),
      ),
    );
    try {
      return await completer.future.timeout(timeout);
    } finally {
      // 超时或完成后清理挂起表, 避免泄漏.
      _pending.remove(id);
    }
  }

  Future<void> close() async {
    _closed = true;
    for (final c in _pending.values) {
      if (!c.isCompleted) {
        c.completeError(StateError('controller closed'));
      }
    }
    _pending.clear();
    try {
      await _socket?.close();
    } catch (_) {}
    _socket = null;
    final server = _server;
    _server = null;
    if (server != null) {
      try {
        await server.close(force: true);
      } catch (_) {}
    }
    if (!_started) return;
    await _statusCtrl.close();
    await _logCtrl.close();
    await _registerCtrl.close();
    await _connCtrl.close();
  }
}
