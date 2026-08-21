import 'dart:convert';
import 'dart:math';

/// 一条 aVPN 配置.
///
/// 同时包含 avpn 原生配置字段 (nexthop/private_key/pkl/fec 等, 通过 json 传入
/// libxavpn.so) 与 Android VpnService 专用字段 (tunAddress/routes/dns 等).
class VpnConfig {
  VpnConfig({
    required this.id,
    required this.name,
    this.mode = 'client',
    this.nexthop = '',
    this.privateKey = '',
    this.publicKey = '',
    List<String>? pkl,
    this.mtuSize = 1450,
    this.keepalive = 60,
    this.dataShards = 0,
    this.parityShards = 0,
    this.compress = '',
    this.obfuscateKey = '',
    List<String>? udpListen,
    List<String>? tcpListen,
    this.subnet = '',
    this.passbyvpn = false,
    List<String>? pushroutes,
    this.pushdns = 0,
    this.ignorePush = false,
    this.c2c = false,
    List<String>? bypassroutes,
    this.tunAddress = '',
    this.tunPrefix = 0,
    List<String>? routes,
    List<String>? dns,
    this.testUrl = 'https://google.com',
    this.bypassCn = false,
  }) : pkl = pkl ?? [],
       udpListen = udpListen ?? [],
       tcpListen = tcpListen ?? [],
       pushroutes = pushroutes ?? [],
       bypassroutes = bypassroutes ?? [],
       routes = routes ?? [],
       dns = dns ?? [];

  String id;
  String name;
  String mode; // client | gateway

  // ---- client ----
  String nexthop; // 支持 "host:port" / "udp://host:port" / "tcp://host:port"

  // ---- 密钥 ----
  String privateKey;
  String publicKey;
  List<String> pkl;

  // ---- 传输参数 ----
  int mtuSize;
  int keepalive;
  int dataShards;
  int parityShards;
  String compress; // '' | deflate | lz4 | zstd
  String obfuscateKey;

  // ---- gateway ----
  List<String> udpListen;
  List<String> tcpListen;
  String subnet;
  bool passbyvpn;
  List<String> pushroutes;
  int pushdns;
  bool ignorePush;
  bool c2c;
  List<String> bypassroutes;

  // ---- Android VpnService ----
  String tunAddress;
  int tunPrefix;
  List<String> routes;
  List<String> dns;

  // ---- UI 工具 ----
  String testUrl; // 测试连接的 URL, 用于运行页测量 VPN 延迟.

  /// 绕过中国大陆: 拉取中国 IP 段, 仅将非中国段接入 VPN,
  /// 中国大陆流量走系统物理网络直连.
  bool bypassCn;

  /// 生成新的配置 id (时间戳 + 随机后缀).
  static String newId() {
    final rand = Random.secure();
    final ts = DateTime.now().microsecondsSinceEpoch.toRadixString(16);
    final suffix = List.generate(
      8,
      (_) => rand.nextInt(0x100).toRadixString(16).padLeft(2, '0'),
    ).join();
    return '$ts$suffix';
  }

  /// 解析 subnet "a.b.c.d/prefix", 返回 (网络地址, 前缀); 无效返回 null.
  static (int, int)? parseSubnet(String subnet) {
    final s = subnet.trim();
    final slash = s.indexOf('/');
    if (slash <= 0) return null;
    final host = s.substring(0, slash).trim();
    final prefix = int.tryParse(s.substring(slash + 1).trim());
    if (prefix == null || prefix < 0 || prefix > 32) return null;
    final parts = host.split('.');
    if (parts.length != 4) return null;
    final octets = <int>[];
    for (final p in parts) {
      final o = int.tryParse(p);
      if (o == null || o < 0 || o > 255) return null;
      octets.add(o);
    }
    final ip =
        (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    // 掩码到网络地址, 避免主机位非零.
    final mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;
    return (ip & mask, prefix);
  }

  static String _ipToString(int v) =>
      '${(v >> 24) & 0xff}.${(v >> 16) & 0xff}.${(v >> 8) & 0xff}.${v & 0xff}';

  /// 计算本端 tun 地址与前缀: 客户端取网络地址+2 (服务端首个分配地址),
  /// 网关取网络地址+1 (网关自身). subnet 缺失或非法时退回手动 tunAddress
  /// 或默认 10.8.0.2/24 (向后兼容旧配置).
  (String, int) deriveTun() {
    final parsed = parseSubnet(subnet);
    if (parsed != null) {
      final (net, prefix) = parsed;
      final offset = mode == 'gateway' ? 1 : 2;
      return (_ipToString(net + offset), prefix);
    }
    if (tunAddress.trim().isNotEmpty && tunPrefix > 0) {
      return (tunAddress.trim(), tunPrefix);
    }
    return ('10.8.0.2', 24);
  }

  /// 校验配置, 返回错误描述列表; 为空表示可运行.
  List<String> validate() {
    final errors = <String>[];
    if (mode != 'client' && mode != 'gateway') {
      errors.add('模式无效: $mode');
    }
    if (mode == 'client' && nexthop.trim().isEmpty) {
      errors.add('客户端模式必须填写 nexthop');
    }
    if (mode == 'client' && publicKey.trim().isEmpty) {
      errors.add('客户端模式必须填写对端公钥 public_key');
    }
    if (mtuSize < 576 || mtuSize > 65535) {
      errors.add('MTU 需在 576~65535 之间');
    }
    if (keepalive <= 0) {
      errors.add('keepalive 必须大于 0');
    }
    if (dataShards < 0 || parityShards < 0) {
      errors.add('FEC 份数不能为负数');
    }
    if (mode == 'gateway' && subnet.isEmpty) {
      errors.add('网关模式必须填写虚拟子网 subnet');
    }
    if (subnet.trim().isEmpty && tunAddress.trim().isEmpty) {
      errors.add('请填写虚拟子网 subnet (用于自动推导 TUN 地址)');
    }
    final url = testUrl.trim();
    if (url.isNotEmpty && !url.startsWith('http://') && !url.startsWith('https://')) {
      errors.add('测试连接需以 http:// 或 https:// 开头');
    }
    return errors;
  }

  VpnConfig copy() => VpnConfig.fromJson(toJson());

  /// 传给 libxavpn.so 的启动/更新配置 json (键名与 xavpn 配置解析一致).
  String toAvpnJson() {
    final map = <String, dynamic>{
      'ifdev': '',
      'nexthop': _effectiveNexthop(),
      if (privateKey.isNotEmpty) 'private_key': privateKey,
      if (publicKey.isNotEmpty) 'public_key': publicKey,
      if (pkl.isNotEmpty) 'pkl': pkl,
      'mtu_size': mtuSize,
      'keepalive': keepalive,
      'data_shards': dataShards,
      'parity_shards': parityShards,
      if (compress.isNotEmpty) 'compress': compress,
      if (obfuscateKey.isNotEmpty) 'obfuscate_key': obfuscateKey,
      if (udpListen.isNotEmpty) 'udp_listen': udpListen,
      if (tcpListen.isNotEmpty) 'tcp_listen': tcpListen,
      if (subnet.isNotEmpty) 'subnet': subnet,
      'passbyvpn': passbyvpn,
      if (pushroutes.isNotEmpty) 'pushroutes': pushroutes,
      if (pushdns > 0) 'pushdns': pushdns,
      'ignore_push': ignorePush,
      'c2c': c2c,
      if (bypassroutes.isNotEmpty) 'bypassroutes': bypassroutes,
    };
    return jsonEncode(map);
  }

  /// 网关模式时 nexthop 为空, 依赖 udp_listen/tcp_listen.
  String _effectiveNexthop() {
    if (mode == 'gateway') return '';
    return nexthop.trim();
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'mode': mode,
    'nexthop': nexthop,
    'privateKey': privateKey,
    'publicKey': publicKey,
    'pkl': pkl,
    'mtuSize': mtuSize,
    'keepalive': keepalive,
    'dataShards': dataShards,
    'parityShards': parityShards,
    'compress': compress,
    'obfuscateKey': obfuscateKey,
    'udpListen': udpListen,
    'tcpListen': tcpListen,
    'subnet': subnet,
    'passbyvpn': passbyvpn,
    'pushroutes': pushroutes,
    'pushdns': pushdns,
    'ignorePush': ignorePush,
    'c2c': c2c,
    'bypassroutes': bypassroutes,
    'tunAddress': tunAddress,
    'tunPrefix': tunPrefix,
    'routes': routes,
    'dns': dns,
    'testUrl': testUrl,
    'bypassCn': bypassCn,
  };

  factory VpnConfig.fromJson(Map<String, dynamic> json) => VpnConfig(
    id: json['id'] as String? ?? VpnConfig.newId(),
    name: json['name'] as String? ?? '未命名',
    mode: json['mode'] as String? ?? 'client',
    nexthop: json['nexthop'] as String? ?? '',
    privateKey: json['privateKey'] as String? ?? '',
    publicKey: json['publicKey'] as String? ?? '',
    pkl: _strList(json['pkl']),
    mtuSize: json['mtuSize'] as int? ?? 1450,
    keepalive: json['keepalive'] as int? ?? 60,
    dataShards: json['dataShards'] as int? ?? 0,
    parityShards: json['parityShards'] as int? ?? 0,
    compress: json['compress'] as String? ?? '',
    obfuscateKey: json['obfuscateKey'] as String? ?? '',
    udpListen: _strList(json['udpListen']),
    tcpListen: _strList(json['tcpListen']),
    subnet: json['subnet'] as String? ?? '',
    passbyvpn: json['passbyvpn'] as bool? ?? false,
    pushroutes: _strList(json['pushroutes']),
    pushdns: json['pushdns'] as int? ?? 0,
    ignorePush: json['ignorePush'] as bool? ?? false,
    c2c: json['c2c'] as bool? ?? false,
    bypassroutes: _strList(json['bypassroutes']),
    tunAddress: json['tunAddress'] as String? ?? '',
    tunPrefix: json['tunPrefix'] as int? ?? 0,
    routes: _strList(json['routes']),
    dns: _strList(json['dns']),
    testUrl: json['testUrl'] as String? ?? 'https://google.com',
    bypassCn: json['bypassCn'] as bool? ?? false,
  );

  static List<String> _strList(dynamic v) {
    if (v is List) return v.whereType<String>().toList();
    if (v is String && v.trim().isNotEmpty) {
      return v.trim().split(RegExp(r'[\s,;]+'));
    }
    return [];
  }
}
