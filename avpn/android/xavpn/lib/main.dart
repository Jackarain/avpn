import 'package:flutter/material.dart';

import 'pages/config_list_page.dart';

void main() {
  runApp(const XavpnApp());
}

class XavpnApp extends StatelessWidget {
  const XavpnApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'aVPN',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: const ConfigListPage(),
    );
  }
}
