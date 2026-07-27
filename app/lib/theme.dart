// SPDX-License-Identifier: AGPL-3.0-or-later
import 'package:flutter/material.dart';

import 'palette.dart';

export 'palette.dart';

/// NullChat design system — a calm, privacy-forward palette with a single accent
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
    // Everything below used to fall back to Material's own colours, which is
    // why parts of the app stayed dark-mint no matter which theme was picked.
    appBarTheme: AppBarTheme(
      backgroundColor: p.surface,
      foregroundColor: p.textPrimary,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      iconTheme: IconThemeData(color: p.textMuted),
    ),
    iconTheme: IconThemeData(color: p.textMuted),
    dialogTheme: DialogThemeData(
      backgroundColor: p.surfaceHigh,
      surfaceTintColor: Colors.transparent,
      titleTextStyle: TextStyle(
        color: p.textPrimary,
        fontSize: 18,
        fontWeight: FontWeight.w700,
      ),
      contentTextStyle: TextStyle(color: p.textPrimary, height: 1.4),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: p.surfaceHigh,
      contentTextStyle: TextStyle(color: p.textPrimary),
      actionTextColor: p.accent,
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    listTileTheme: ListTileThemeData(
      iconColor: p.textMuted,
      textColor: p.textPrimary,
    ),
    chipTheme: ChipThemeData(
      backgroundColor: p.surfaceHigh,
      selectedColor: p.accent.withValues(alpha: 0.2),
      side: BorderSide(color: p.border),
      labelStyle: TextStyle(color: p.textMuted, fontWeight: FontWeight.w600),
      secondaryLabelStyle: TextStyle(color: p.accent, fontWeight: FontWeight.w600),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(foregroundColor: p.accent),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: p.accent,
        side: BorderSide(color: p.border),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    segmentedButtonTheme: SegmentedButtonThemeData(
      style: ButtonStyle(
        foregroundColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.selected) ? p.accentInk : p.textMuted,
        ),
        backgroundColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.selected) ? p.accent : p.surfaceHigh,
        ),
        side: WidgetStateProperty.all(BorderSide(color: p.border)),
      ),
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected) ? p.accentInk : p.textMuted,
      ),
      trackColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected) ? p.accent : p.surfaceHigh,
      ),
      trackOutlineColor: WidgetStateProperty.all(p.border),
    ),
    checkboxTheme: CheckboxThemeData(
      fillColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected) ? p.accent : Colors.transparent,
      ),
      checkColor: WidgetStateProperty.all(p.accentInk),
      side: BorderSide(color: p.border, width: 1.5),
    ),
    sliderTheme: SliderThemeData(
      activeTrackColor: p.accent,
      inactiveTrackColor: p.surfaceHigh,
      thumbColor: p.accent,
      overlayColor: p.accent.withValues(alpha: 0.12),
    ),
    progressIndicatorTheme: ProgressIndicatorThemeData(
      color: p.accent,
      linearTrackColor: p.surfaceHigh,
      circularTrackColor: p.surfaceHigh,
    ),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: p.surfaceHigh,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: p.border),
      ),
      textStyle: TextStyle(color: p.textPrimary, fontSize: 12),
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: p.surfaceHigh,
      surfaceTintColor: Colors.transparent,
      textStyle: TextStyle(color: p.textPrimary, fontSize: 14),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    textSelectionTheme: TextSelectionThemeData(
      cursorColor: p.accent,
      selectionColor: p.accent.withValues(alpha: 0.3),
      selectionHandleColor: p.accent,
    ),
    scrollbarTheme: ScrollbarThemeData(
      thumbColor: WidgetStateProperty.all(p.border),
    ),
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
