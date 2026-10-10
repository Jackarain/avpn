import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xavpn/models/vpn_config.dart';
import 'package:xavpn/services/config_share.dart';

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

  test('明文 JSON 也可解析', () {
    final config = VpnConfig(id: 'id-2', name: '家庭', nexthop: '1.2.3.4:1');
    final raw = jsonEncode({
      'type': 'xavpn-config',
      'version': 1,
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
      () => decodeConfigShare('xavpn1:这不是合法的-base64'),
      throwsFormatException,
    );
  });
}
