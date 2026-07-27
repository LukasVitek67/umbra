// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Colour themes. Every screen reads its colours through `UmbraColors`, which
// forwards to the palette active here, so switching a theme is one notifier
// away. The choice is remembered next to the app's data, like the language.

import 'dart:io';

import 'app_dir.dart';

import 'package:flutter/material.dart';

@immutable
class UmbraPalette {
  const UmbraPalette({
    required this.id,
    required this.dark,
    required this.bg,
    required this.surface,
    required this.surfaceHigh,
    required this.border,
    required this.textPrimary,
    required this.textMuted,
    required this.accent,
    required this.accentInk,
    required this.danger,
  });

  final String id;

  /// Light themes need a light [ColorScheme] and darker ink on the accent.
  final bool dark;

  final Color bg;
  final Color surface;
  final Color surfaceHigh;
  final Color border;
  final Color textPrimary;
  final Color textMuted;
  final Color accent;
  final Color accentInk;
  final Color danger;

  /// Derives a full dark palette from a single accent colour: the surfaces get
  /// a barely-there tint of the same hue so a custom colour still looks like a
  /// designed theme instead of a recoloured button.
  factory UmbraPalette.fromAccent(Color accent, {String id = 'custom'}) {
    final hsl = HSLColor.fromColor(accent);
    // Very dark or washed-out picks would be unreadable on a dark background,
    // so the accent is nudged into a range that always has contrast.
    final tuned = HSLColor.fromAHSL(
      1,
      hsl.hue,
      hsl.saturation.clamp(0.35, 1.0),
      hsl.lightness.clamp(0.45, 0.78),
    );
    Color shade(double saturation, double lightness) =>
        HSLColor.fromAHSL(1, hsl.hue, saturation, lightness).toColor();

    final accentColor = tuned.toColor();
    return UmbraPalette(
      id: id,
      dark: true,
      bg: shade(0.22, 0.045),
      surface: shade(0.18, 0.075),
      surfaceHigh: shade(0.16, 0.115),
      border: shade(0.14, 0.175),
      textPrimary: shade(0.15, 0.90),
      textMuted: shade(0.10, 0.62),
      accent: accentColor,
      accentInk: shade(0.55, 0.05),
      danger: const Color(0xFFF2555A),
    );
  }

  /// `mint` for a preset, `custom:FF4FD1C5` for a hand-picked colour.
  String encode() =>
      id == 'custom' ? 'custom:${accent.toARGB32().toRadixString(16).padLeft(8, '0')}' : id;

  static UmbraPalette? decode(String raw) {
    final v = raw.trim();
    if (v.startsWith('custom:')) {
      final hex = int.tryParse(v.substring(7), radix: 16);
      if (hex == null) return null;
      return UmbraPalette.fromAccent(Color(hex));
    }
    return UmbraPalettes.byId(v);
  }
}

/// The built-in themes, in the order they appear in Settings.
class UmbraPalettes {
  /// The original NullChat look: near-black with a mint accent.
  static const mint = UmbraPalette(
    id: 'mint',
    dark: true,
    bg: Color(0xFF0A0C10),
    surface: Color(0xFF12151C),
    surfaceHigh: Color(0xFF1A1F29),
    border: Color(0xFF232935),
    textPrimary: Color(0xFFE6EAF2),
    textMuted: Color(0xFF8A94A6),
    accent: Color(0xFF4FD1C5),
    accentInk: Color(0xFF04120F),
    danger: Color(0xFFF2555A),
  );

  static const azure = UmbraPalette(
    id: 'azure',
    dark: true,
    bg: Color(0xFF080B12),
    surface: Color(0xFF10151F),
    surfaceHigh: Color(0xFF171E2C),
    border: Color(0xFF212B3D),
    textPrimary: Color(0xFFE4EAF6),
    textMuted: Color(0xFF8791A6),
    accent: Color(0xFF5AA9FF),
    accentInk: Color(0xFF04101F),
    danger: Color(0xFFF2555A),
  );

  static const violet = UmbraPalette(
    id: 'violet',
    dark: true,
    bg: Color(0xFF0B0912),
    surface: Color(0xFF14111E),
    surfaceHigh: Color(0xFF1C182B),
    border: Color(0xFF272138),
    textPrimary: Color(0xFFE9E5F5),
    textMuted: Color(0xFF9289A8),
    accent: Color(0xFFA78BFA),
    accentInk: Color(0xFF130A26),
    danger: Color(0xFFF2555A),
  );

  static const amber = UmbraPalette(
    id: 'amber',
    dark: true,
    bg: Color(0xFF0D0B08),
    surface: Color(0xFF17130D),
    surfaceHigh: Color(0xFF211B12),
    border: Color(0xFF2E2619),
    textPrimary: Color(0xFFF2EADC),
    textMuted: Color(0xFFA3947C),
    accent: Color(0xFFE8A33D),
    accentInk: Color(0xFF1A1004),
    danger: Color(0xFFF2555A),
  );

  static const rose = UmbraPalette(
    id: 'rose',
    dark: true,
    bg: Color(0xFF0F0A0C),
    surface: Color(0xFF191115),
    surfaceHigh: Color(0xFF23181D),
    border: Color(0xFF322028),
    textPrimary: Color(0xFFF5E6EB),
    textMuted: Color(0xFFAB8E99),
    accent: Color(0xFFF2789B),
    accentInk: Color(0xFF1E0710),
    danger: Color(0xFFF2555A),
  );

  /// The one light theme, for people who work in a bright room.
  static const day = UmbraPalette(
    id: 'day',
    dark: false,
    bg: Color(0xFFF4F6FA),
    surface: Color(0xFFFFFFFF),
    surfaceHigh: Color(0xFFEBEFF5),
    border: Color(0xFFD6DCE6),
    textPrimary: Color(0xFF0F141B),
    textMuted: Color(0xFF5C6675),
    accent: Color(0xFF0E9484),
    accentInk: Color(0xFFFFFFFF),
    danger: Color(0xFFC8323C),
  );

  static const all = <UmbraPalette>[mint, azure, violet, amber, rose, day];

  static UmbraPalette? byId(String id) {
    for (final p in all) {
      if (p.id == id) return p;
    }
    return null;
  }
}

/// Holds the active palette and remembers it between runs.
class UmbraTheme {
  static UmbraPalette _palette = UmbraPalettes.mint;
  static File? _file;

  static UmbraPalette get palette => _palette;

  /// Rebuilds the app when the theme changes.
  static final ValueNotifier<UmbraPalette> notifier =
      ValueNotifier<UmbraPalette>(UmbraPalettes.mint);

  /// Load the stored choice (call once at startup).
  static Future<void> load() async {
    try {
      final dir = Directory(await AppDir.path());
      _file = File('${dir.path}${Platform.pathSeparator}theme.txt');
      if (await _file!.exists()) {
        final stored = UmbraPalette.decode(await _file!.readAsString());
        if (stored != null) {
          _palette = stored;
          notifier.value = stored;
        }
      }
    } catch (_) {
      // A theme is a nicety; never block startup on it.
    }
  }

  static Future<void> set(UmbraPalette palette) async {
    _palette = palette;
    notifier.value = palette;
    try {
      await _file?.writeAsString(palette.encode());
    } catch (_) {}
  }

  /// Any colour the user picks in the wheel becomes a full dark theme.
  static Future<void> setCustomAccent(Color accent) =>
      set(UmbraPalette.fromAccent(accent));
}
