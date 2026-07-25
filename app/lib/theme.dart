// SPDX-License-Identifier: AGPL-3.0-or-later
import 'package:flutter/material.dart';

import 'palette.dart';

export 'palette.dart';

/// Umbra design system — a calm, privacy-forward palette with a single accent
/// (reads as "secure/encrypted"), deliberately not the generic Material default.
///
/// These are getters, not constants: they follow whichever [UmbraPalette] the
/// user picked in Settings, so the whole UI recolours without touching call sites.
class UmbraColors {
  static Color get bg => UmbraTheme.palette.bg;
  static Color get surface => UmbraTheme.palette.surface;
  static Color get surfaceHigh => UmbraTheme.palette.surfaceHigh;
  static Color get border => UmbraTheme.palette.border;
  static Color get textPrimary => UmbraTheme.palette.textPrimary;
  static Color get textMuted => UmbraTheme.palette.textMuted;
  static Color get accent => UmbraTheme.palette.accent;
  static Color get accentInk => UmbraTheme.palette.accentInk;
  static Color get danger => UmbraTheme.palette.danger;
}

ThemeData umbraTheme() {
  final p = UmbraTheme.palette;
  final scheme = p.dark
      ? ColorScheme.dark(
          surface: p.bg,
          primary: p.accent,
          onPrimary: p.accentInk,
          secondary: p.accent,
          error: p.danger,
          onSurface: p.textPrimary,
        )
      : ColorScheme.light(
          surface: p.bg,
          primary: p.accent,
          onPrimary: p.accentInk,
          secondary: p.accent,
          error: p.danger,
          onSurface: p.textPrimary,
        );

  return ThemeData(
    useMaterial3: true,
    brightness: p.dark ? Brightness.dark : Brightness.light,
    colorScheme: scheme,
    scaffoldBackgroundColor: p.bg,
    textTheme: TextTheme(
      headlineMedium: TextStyle(
        fontWeight: FontWeight.w800,
        letterSpacing: -0.5,
        color: p.textPrimary,
      ),
      titleLarge: TextStyle(fontWeight: FontWeight.w700, color: p.textPrimary),
      titleMedium: TextStyle(fontWeight: FontWeight.w600, color: p.textPrimary),
      bodyMedium: TextStyle(color: p.textPrimary, height: 1.4),
      bodySmall: TextStyle(color: p.textMuted, height: 1.35),
      labelSmall: TextStyle(color: p.textMuted, letterSpacing: 0.3),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: p.surfaceHigh,
      hintStyle: TextStyle(color: p.textMuted),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: p.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: p.accent, width: 1.5),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: p.accent,
        foregroundColor: p.accentInk,
        disabledBackgroundColor: p.surfaceHigh,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
      ),
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: p.surface,
      selectedIconTheme: IconThemeData(color: p.accent),
      unselectedIconTheme: IconThemeData(color: p.textMuted),
      selectedLabelTextStyle: TextStyle(color: p.accent, fontWeight: FontWeight.w600),
      unselectedLabelTextStyle: TextStyle(color: p.textMuted),
      indicatorColor: p.accent.withValues(alpha: 0.13),
    ),
    dividerTheme: DividerThemeData(color: p.border, thickness: 1),
  );
}

/// A rounded panel used throughout the app.
class Panel extends StatelessWidget {
  const Panel({super.key, required this.child, this.padding});
  final Widget child;
  final EdgeInsetsGeometry? padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: padding ?? const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: UmbraColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: UmbraColors.border),
      ),
      child: child,
    );
  }
}

/// Small status pill (e.g. "Přes Tor", "Ověřeno").
class Pill extends StatelessWidget {
  const Pill(this.text, {super.key, this.color, this.icon});
  final String text;

  /// Defaults to the accent of the active theme.
  final Color? color;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final color = this.color ?? UmbraColors.accent;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[Icon(icon, size: 13, color: color), const SizedBox(width: 5)],
          Text(text, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }
}
