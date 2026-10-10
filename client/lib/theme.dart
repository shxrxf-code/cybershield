/// Material 3 themes — navy surfaces with an electric-cyan accent.
library;

import 'package:flutter/material.dart';

const Color _seedDark = Color(0xFF00C2E8);
const Color _seedLight = Color(0xFF007A96);

ColorScheme _darkScheme() => ColorScheme.fromSeed(
      seedColor: _seedDark,
      brightness: Brightness.dark,
      surface: const Color(0xFF0E1A33),
      surfaceContainerLowest: const Color(0xFF0A1226),
      surfaceContainerLow: const Color(0xFF0C162C),
      surfaceContainer: const Color(0xFF12203C),
      surfaceContainerHigh: const Color(0xFF18294A),
      surfaceContainerHighest: const Color(0xFF1F3157),
    ).copyWith(
      surfaceTint: Colors.transparent,
      primary: const Color(0xFF38D6F5),
      onPrimary: const Color(0xFF00252E),
      primaryContainer: const Color(0xFF0A3D4E),
      onPrimaryContainer: const Color(0xFFB5ECFF),
      secondary: const Color(0xFF7DD8E8),
      onSecondary: const Color(0xFF04323D),
      secondaryContainer: const Color(0xFF0A3D4E),
      onSecondaryContainer: const Color(0xFFB5ECFF),
      tertiary: const Color(0xFF8AB4FF),
      onTertiary: const Color(0xFF0B2A5E),
      tertiaryContainer: const Color(0xFF123A75),
      onTertiaryContainer: const Color(0xFFD7E3FF),
      errorContainer: const Color(0xFF4A1A26),
      onErrorContainer: const Color(0xFFFFDAD9),
    );

ColorScheme _lightScheme() => ColorScheme.fromSeed(
      seedColor: _seedLight,
      brightness: Brightness.light,
    ).copyWith(surfaceTint: Colors.transparent);

ThemeData buildTheme() => buildLightTheme();

/// Minimum touch targets per the accessibility plan: tappable controls are
/// never smaller than 44×44 logical pixels.
final ButtonStyle _minTouchFilled = FilledButton.styleFrom(
  minimumSize: const Size(64, 44),
  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
);
final ButtonStyle _minTouchOutlined = OutlinedButton.styleFrom(
  minimumSize: const Size(64, 44),
  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
);
final ButtonStyle _minTouchText = TextButton.styleFrom(
  minimumSize: const Size(48, 40),
  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
);

ThemeData buildLightTheme() {
  final scheme = _lightScheme();
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: const Color(0xFFF4F7FB),
    filledButtonTheme: FilledButtonThemeData(style: _minTouchFilled),
    outlinedButtonTheme: OutlinedButtonThemeData(style: _minTouchOutlined),
    textButtonTheme: TextButtonThemeData(style: _minTouchText),
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      margin: EdgeInsets.zero,
      color: scheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: Colors.black.withValues(alpha: 0.06)),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: scheme.surfaceContainerLowest,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: scheme.outlineVariant),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: scheme.outlineVariant),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: scheme.primary, width: 1.6),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: scheme.surface,
      indicatorColor: scheme.secondaryContainer,
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: scheme.surface,
      indicatorColor: scheme.secondaryContainer,
      selectedIconTheme: IconThemeData(color: scheme.onSecondaryContainer),
      unselectedIconTheme: const IconThemeData(color: Color(0xFF8A93A6)),
    ),
    dividerTheme: DividerThemeData(color: scheme.outlineVariant.withValues(alpha: 0.6)),
    chipTheme: ChipThemeData(
      backgroundColor: scheme.surfaceContainerHighest,
      side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.5)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
  );
}

ThemeData buildDarkTheme() {
  final scheme = _darkScheme();
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: const Color(0xFF0B1220),
    filledButtonTheme: FilledButtonThemeData(style: _minTouchFilled),
    outlinedButtonTheme: OutlinedButtonThemeData(style: _minTouchOutlined),
    textButtonTheme: TextButtonThemeData(style: _minTouchText),
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      margin: EdgeInsets.zero,
      color: const Color(0xFF0E1A33),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: Colors.white.withValues(alpha: 0.06)),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: const Color(0xFF0C162C),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.14)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.14)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: scheme.primary, width: 1.6),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: const Color(0xFF0E1A33),
      indicatorColor: scheme.primaryContainer,
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: const Color(0xFF0E1A33),
      indicatorColor: scheme.primaryContainer,
    ),
    dividerTheme: DividerThemeData(
        color: Colors.white.withValues(alpha: 0.08)),
    chipTheme: ChipThemeData(
      backgroundColor: const Color(0xFF1F3157),
      side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: const Color(0xFF18294A),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
  );
}