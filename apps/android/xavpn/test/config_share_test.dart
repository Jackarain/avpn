import 'dart:convert';
import 'dart:io' show ZLibCodec, ZLibOption;

import 'package:flutter_test/flutter_test.dart';
import 'package:xavpn/models/vpn_config.dart';
import 'package:xavpn/services/config_share.dart';

/// 旧版 (v1) 无字典 deflate 编码, 用于验证向后兼容.
String _encodeV1(VpnConfig config) {
  final json = jsonEncode({
    'type': 'xavpn-config',
    'version': 1,
    'config': config.toJson(),
  });
  final packed = ZLibCodec(
    level: ZLibOption.maxLevel,
  ).encode(utf8.encode(json));
  return 'xavpn1:${base64Url.encode(packed)}';
}

void main() {
  test('编码后可原样解回', () {
    final config = VpnConfig(
      id: 'id-1',
      name: '办公室',
      mode: 'client',
      nexthop: 'example.com:19090',
      privateKey: 'priv',
      publicKey: 'pub',
      pkl: ['a', 'b'],
      mtuSize: 1400,
      keepalive: 30,
      compress: 'zstd',
      subnet: '10.8.0.0/24',
      routes: ['0.0.0.0/1', '128.0.0.0/1'],
      dns: ['1.1.1.1'],
      bypassCn: true,
      dnsIntercept: true,
      dohUrl: 'https://1.1.1.1/dns-query',
      directDns: '114.114.114.114',
    );

    final decoded = decodeConfigShare(encodeConfigShare(config));

    expect(decoded.toJson(), config.toJson());
  });

  test('当前编码带 v2 字典前缀', () {
    final config = VpnConfig(id: 'id-2', name: 'x', nexthop: 'a:1');
    expect(encodeConfigShare(config).startsWith('xavpn2:'), isTrue);
  });

  test('兼容旧版 v1 (无字典) 二维码', () {
    final config = VpnConfig(id: 'id-3', name: '旧版', nexthop: 'b:2');
    expect(decodeConfigShare(_encodeV1(config)).name, '旧版');
  });

  test('字典压缩比无字典更小', () {
    final config = VpnConfig(
      id: 'id-4',
      name: '我的节点',
      mode: 'client',
      nexthop: 'node-42.vpn.example.org:19090',
      privateKey: 'kR8mQ2xVn0pZ7cT4wL9bY6dH1sA3fG5jU2oI8eN4rM=',
      publicKey: 'Zq1wE5rT9yU3iO7pA2sD6fG0hJ4kL8xV1bN5mQ9zC3v=',
      bypassCn: true,
      dnsIntercept: true,
    );
    expect(
      encodeConfigShare(config).length,
      lessThan(_encodeV1(config).length),
    );
  });

  test('明文 JSON 也可解析', () {
    final config = VpnConfig(id: 'id-5', name: '家庭', nexthop: '1.2.3.4:1');
    final raw = jsonEncode({
      'type': 'xavpn-config',
      'version': 2,
      'config': config.toJson(),
    });
    expect(decodeConfigShare(raw).name, '家庭');
  });

  test('非本应用二维码抛出 FormatException', () {
    expect(
      () => decodeConfigShare('https://example.com/whatever'),
      throwsFormatException,
    );
  });

  test('内容损坏抛出 FormatException', () {
    expect(
      () => decodeConfigShare('xavpn2:这不是合法的-base64'),
      throwsFormatException,
    );
  });
}
