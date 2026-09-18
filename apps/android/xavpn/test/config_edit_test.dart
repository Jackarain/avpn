import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xavpn/models/vpn_config.dart';
import 'package:xavpn/pages/config_edit_page.dart';

Future<void> _pumpEdit(WidgetTester tester, VpnConfig config) async {
  await tester.pumpWidget(
    MaterialApp(home: ConfigEditPage(config: config, isNew: true)),
  );
  await tester.pumpAndSettle();
}

/// 表单里 TextField 也带 Scrollable, 这里只滚最外层列表.
Finder get _list => find.byType(Scrollable).first;

void main() {
  testWidgets('客户端配置按分组展示, 网关分组不出现', (tester) async {
    await _pumpEdit(
      tester,
      VpnConfig(id: '1', name: '办公室', mode: 'client', nexthop: '1.2.3.4:19090'),
    );

    expect(find.text('基本'), findsOneWidget);
    expect(find.text('密钥'), findsOneWidget);
    expect(find.text('Nexthop 服务器'), findsOneWidget);
    expect(find.text('网关监听'), findsNothing);
    expect(find.text('网关推送与选项'), findsNothing);
  });

  testWidgets('网关配置展示监听与推送分组, 不出现 nexthop', (tester) async {
    await _pumpEdit(tester, VpnConfig(id: '2', name: '网关', mode: 'gateway'));

    expect(find.text('Nexthop 服务器'), findsNothing);
    await tester.scrollUntilVisible(find.text('网关监听'), 200, scrollable: _list);
    expect(find.text('网关监听'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('网关推送与选项'),
      200,
      scrollable: _list,
    );
    expect(find.text('passbyvpn (默认全局出口)'), findsOneWidget);
  });

  testWidgets('DNS 拦截分流开启后展示 DoH 等子项', (tester) async {
    await _pumpEdit(
      tester,
      VpnConfig(id: '3', name: '分流', mode: 'client', dnsIntercept: true),
    );

    await tester.scrollUntilVisible(
      find.text('启用 DNS 拦截分流'),
      200,
      scrollable: _list,
    );
    await tester.scrollUntilVisible(
      find.text('DoH 服务地址'),
      200,
      scrollable: _list,
    );
    expect(find.text('直连 DNS 服务器'), findsOneWidget);
    expect(find.text('gfwlist 下载地址'), findsOneWidget);
  });
}
