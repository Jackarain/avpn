import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:xavpn/models/vpn_config.dart';
import 'package:xavpn/services/storage_service.dart';

void main() {
  group('VpnConfig', () {
    test('json 往返保持一致', () {
      final c = VpnConfig(
        id: 'abc',
        name: '测试',
        mode: 'gateway',
        nexthop: '1.2.3.4:19090',
        privateKey: 'k1',
        pkl: ['pk1', 'pk2'],
        mtuSize: 1400,
        keepalive: 30,
        dataShards: 2,
        parityShards: 1,
        compress: 'lz4',
        obfuscateKey: 'ob',
        udpListen: ['0.0.0.0:19090'],
        subnet: '10.9.0.0/16',
        passbyvpn: true,
        pushroutes: ['10.0.0.0/8'],
        tunAddress: '10.8.0.2',
        routes: ['10.9.0.0/16'],
        dns: ['8.8.8.8'],
      );
      final restored = VpnConfig.fromJson(c.toJson());
      expect(restored.id, c.id);
      expect(restored.name, c.name);
      expect(restored.mode, 'gateway');
      expect(restored.nexthop, c.nexthop);
      expect(restored.pkl, ['pk1', 'pk2']);
      expect(restored.udpListen, ['0.0.0.0:19090']);
      expect(restored.pushroutes, ['10.0.0.0/8']);
      expect(restored.routes, ['10.9.0.0/16']);
      expect(restored.compress, 'lz4');
      expect(restored.passbyvpn, true);
    });

    test('toAvpnJson 仅含 avpn 原生键, 网关模式 nexthop 为空', () {
      final c = VpnConfig(
        id: 'abc',
        name: '网关',
        mode: 'gateway',
        nexthop: '1.2.3.4:19090',
        mtuSize: 1400,
      );
      final map = jsonDecode(c.toAvpnJson()) as Map<String, dynamic>;
      expect(map['nexthop'], '');
      expect(map['mtu_size'], 1400);
      expect(map.containsKey('ptun_fd'), false);
      expect(map.containsKey('routes'), false);
      expect(map.containsKey('name'), false);
    });

    test('客户端模式 toAvpnJson 保留 nexthop', () {
      final c = VpnConfig(
        id: 'abc',
        name: '客户端',
        mode: 'client',
        nexthop: 'udp://1.2.3.4:19090',
      );
      final map = jsonDecode(c.toAvpnJson()) as Map<String, dynamic>;
      expect(map['nexthop'], 'udp://1.2.3.4:19090');
    });

    test('deriveTun 由 subnet 自动推导', () {
      final client = VpnConfig(
        id: '1',
        name: 'c',
        mode: 'client',
        subnet: '10.10.0.0/16',
      );
      expect(client.deriveTun(), ('10.10.0.2', 16));

      final gateway = VpnConfig(
        id: '2',
        name: 'g',
        mode: 'gateway',
        subnet: '10.10.0.0/16',
      );
      expect(gateway.deriveTun(), ('10.10.0.1', 16));

      // 非 8 位对齐子网按网络地址推导.
      final odd = VpnConfig(
        id: '3',
        name: 'o',
        mode: 'client',
        subnet: '10.10.1.5/24',
      );
      expect(odd.deriveTun(), ('10.10.1.2', 24));

      // subnet 缺失时退回手动地址.
      final manual = VpnConfig(
        id: '4',
        name: 'm',
        mode: 'client',
        tunAddress: '10.8.0.2',
        tunPrefix: 24,
      );
      expect(manual.deriveTun(), ('10.8.0.2', 24));

      // 全部缺失时使用兼容默认.
      final fallback = VpnConfig(id: '5', name: 'f', mode: 'client');
      expect(fallback.deriveTun(), ('10.8.0.2', 24));
    });

    test('newId 每次生成不同 id', () {
      final ids = {for (var i = 0; i < 100; i++) VpnConfig.newId()};
      expect(ids.length, 100);
    });

    test('validate 报告缺失与非法字段', () {
      final bad = VpnConfig(
        id: '1',
        name: '坏配置',
        mode: 'client',
        nexthop: '',
        mtuSize: 10,
        keepalive: 0,
      );
      final errors = bad.validate();
      expect(errors, contains('客户端模式必须填写 nexthop'));
      expect(errors, contains('客户端模式必须填写对端公钥 public_key'));
      expect(errors, contains('MTU 需在 576~65535 之间'));
      expect(errors, contains('keepalive 必须大于 0'));
      expect(errors, contains('请填写虚拟子网 subnet (用于自动推导 TUN 地址)'));

      final ok = VpnConfig(
        id: '2',
        name: '好配置',
        mode: 'client',
        nexthop: '1.2.3.4:19090',
        publicKey: 'aGVsbG8=',
        subnet: '10.10.0.0/16',
      );
      expect(ok.validate(), isEmpty);
    });
  });

  group('StorageService', () {
    setUp(() {
      SharedPreferences.setMockInitialValues({});
    });

    test('配置保存与加载往返', () async {
      final storage = StorageService();
      final configs = [
        VpnConfig(id: '1', name: 'a', mode: 'client', nexthop: 'x:1'),
        VpnConfig(id: '2', name: 'b', mode: 'gateway'),
      ];
      await storage.saveConfigs(configs);
      final loaded = await storage.loadConfigs();
      expect(loaded.length, 2);
      expect(loaded[0].name, 'a');
      expect(loaded[1].mode, 'gateway');
    });

    test('运行状态持久化与清除', () async {
      final storage = StorageService();
      expect(await storage.loadRunState(), isNull);
      await storage.saveRunState('cfg-1', 45678);
      final state = await storage.loadRunState();
      expect(state, isNotNull);
      expect(state!.$1, 'cfg-1');
      expect(state.$2, 45678);
      await storage.clearRunState();
      expect(await storage.loadRunState(), isNull);
    });

    test('损坏的存储内容安全回退为空列表', () async {
      SharedPreferences.setMockInitialValues({'xavpn_configs_v1': 'not json'});
      final storage = StorageService();
      expect(await storage.loadConfigs(), isEmpty);
    });
  });

  group('VpnConfig dns intercept', () {
    test('toAvpnJson 包含 DNS 拦截字段', () {
      final c = VpnConfig(
        id: 'abc',
        name: '测试',
        mode: 'client',
        nexthop: '1.2.3.4:19090',
        publicKey: 'pk',
        dnsIntercept: true,
        dohUrl: 'https://cloudflare-dns.com/dns-query',
        directDns: '223.5.5.5',
        gfwlistUrl: 'https://example.com/gfwlist.txt',
      );
      final map = jsonDecode(c.toAvpnJson()) as Map<String, dynamic>;
      expect(map['dns_intercept'], true);
      expect(map['dns_doh_url'], 'https://cloudflare-dns.com/dns-query');
      expect(map['dns_direct'], '223.5.5.5');
      expect(map['gfwlist_url'], 'https://example.com/gfwlist.txt');
      expect(map['gfwlist_cache'], '/data/data/com.jackarain.xavpn/files/gfwlist.txt');
    });

    test('toAvpnJson 未启用 DNS 拦截时不传 doh/直连字段', () {
      final c = VpnConfig(
        id: 'abc',
        name: '测试',
        mode: 'client',
        nexthop: '1.2.3.4:19090',
        publicKey: 'pk',
      );
      final map = jsonDecode(c.toAvpnJson()) as Map<String, dynamic>;
      expect(map['dns_intercept'], false);
      expect(map.containsKey('dns_doh_url'), false);
      expect(map.containsKey('dns_direct'), false);
      expect(map.containsKey('gfwlist_url'), false);
    });

    test('json 往返保留 DNS 拦截字段', () {
      final c = VpnConfig(
        id: 'abc',
        name: '测试',
        dnsIntercept: true,
        dohUrl: 'https://dns.google/dns-query',
        directDns: '1.1.1.1',
        gfwlistUrl: 'https://a.b/c.txt',
      );
      final restored = VpnConfig.fromJson(c.toJson());
      expect(restored.dnsIntercept, true);
      expect(restored.dohUrl, 'https://dns.google/dns-query');
      expect(restored.directDns, '1.1.1.1');
      expect(restored.gfwlistUrl, 'https://a.b/c.txt');
    });

    test('启用 DNS 拦截时校验 DoH 与直连 DNS', () {
      final c = VpnConfig(
        id: 'abc',
        name: '测试',
        mode: 'client',
        nexthop: '1.2.3.4:19090',
        publicKey: 'pk',
        dnsIntercept: true,
        dohUrl: 'not-a-url',
        directDns: '',
      );
      final errors = c.validate();
      expect(errors.any((e) => e.contains('DoH')), true);
      expect(errors.any((e) => e.contains('直连 DNS')), true);
    });
  });
}
