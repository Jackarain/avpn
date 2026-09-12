import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:xavpn/models/vpn_config.dart';
import 'package:xavpn/pages/config_list_page.dart';
import 'package:xavpn/services/app_session.dart';

void main() {
  testWidgets('配置列表展示已保存配置', (tester) async {
    SharedPreferences.setMockInitialValues({
      'xavpn_configs_v1': jsonEncode([
        VpnConfig(id: '1', name: '办公室', mode: 'client', nexthop: '1.2.3.4:19090')
            .toJson(),
        VpnConfig(id: '2', name: '家庭网关', mode: 'gateway').toJson(),
      ]),
    });
    AppSession.instance.endRun();

    await tester.pumpWidget(const MaterialApp(home: ConfigListPage()));
    await tester.pumpAndSettle();

    expect(find.text('办公室'), findsOneWidget);
    expect(find.text('家庭网关'), findsOneWidget);
  });

  testWidgets('删除配置需确认', (tester) async {
    SharedPreferences.setMockInitialValues({
      'xavpn_configs_v1': jsonEncode([
        VpnConfig(id: '1', name: '待删除', mode: 'client', nexthop: 'x:1')
            .toJson(),
      ]),
    });
    AppSession.instance.endRun();

    await tester.pumpWidget(const MaterialApp(home: ConfigListPage()));
    await tester.pumpAndSettle();

    // 打开配置菜单并选择删除.
    await tester.tap(find.byType(PopupMenuButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('删除'));
    await tester.pumpAndSettle();

    // 确认对话框出现, 取消则保留.
    expect(find.text('确定删除「待删除」吗?'), findsOneWidget);
    await tester.tap(find.text('取消'));
    await tester.pumpAndSettle();
    expect(find.text('待删除'), findsOneWidget);

    // 再次删除并确认.
    await tester.tap(find.byType(PopupMenuButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('删除'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('删除'));
    await tester.pumpAndSettle();
    expect(find.text('待删除'), findsNothing);
  });
}
