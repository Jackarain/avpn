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
      theme: _buildTheme(Brightness.light),
      darkTheme: _buildTheme(Brightness.dark),
      home: const ConfigListPage(),
    );
  }

  /// 扁平矩形 (无圆角) 风格主题.
  ThemeData _buildTheme(Brightness brightness) {
    final scheme = ColorScheme.fromSeed(
      seedColor: Colors.indigo,
      brightness: brightness,
    );
    final square = RoundedRectangleBorder(borderRadius: BorderRadius.zero);
    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,
      cardTheme: CardThemeData(
        shape: square,
        elevation: 0,
        margin: const EdgeInsets.symmetric(vertical: 4),
      ),
      dialogTheme: DialogThemeData(shape: square),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: square,
      ),
      inputDecorationTheme: InputDecorationTheme(
        border: const OutlineInputBorder(borderRadius: BorderRadius.zero),
        enabledBorder: const OutlineInputBorder(
          borderRadius: BorderRadius.zero,
        ),
        focusedBorder: const OutlineInputBorder(
          borderRadius: BorderRadius.zero,
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(shape: square),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(shape: square),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(shape: square),
      ),
      tabBarTheme: TabBarThemeData(
        indicatorSize: TabBarIndicatorSize.tab,
        indicator: BoxDecoration(
          color: scheme.primary,
          borderRadius: BorderRadius.zero,
        ),
      ),
    );
  }
}
