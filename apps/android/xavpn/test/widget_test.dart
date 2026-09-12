import 'package:flutter_test/flutter_test.dart';
import 'package:xavpn/main.dart';

void main() {
  testWidgets('app builds', (tester) async {
    await tester.pumpWidget(const XavpnApp());
    expect(find.text('aVPN 配置'), findsOneWidget);
  });
}
