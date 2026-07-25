// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The theme is the piece of UI worth testing without the core behind it: every
// screen reads its colours through UmbraColors, so a palette that does not
// reach the widgets means the whole app stays mint-green whatever you pick.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:umbra/theme.dart';

void main() {
  testWidgets('widgets follow the selected palette', (tester) async {
    await UmbraTheme.set(UmbraPalettes.day);
    expect(UmbraColors.accent, UmbraPalettes.day.accent);

    await tester.pumpWidget(
      MaterialApp(
        theme: umbraTheme(),
        home: const Scaffold(body: Panel(child: Pill('Tor', icon: Icons.bolt))),
      ),
    );

    final theme = Theme.of(tester.element(find.byType(Scaffold)));
    expect(theme.brightness, Brightness.light);
    expect(theme.colorScheme.primary, UmbraPalettes.day.accent);
    expect(theme.scaffoldBackgroundColor, UmbraPalettes.day.bg);

    await UmbraTheme.set(UmbraPalettes.mint);
    expect(UmbraColors.bg, UmbraPalettes.mint.bg);
  });

  test('a custom accent still produces a readable palette', () {
    // Something almost black must still come out as a visible accent.
    final palette = UmbraPalette.fromAccent(const Color(0xFF050505));
    expect(palette.dark, isTrue);
    expect(HSLColor.fromColor(palette.accent).lightness, greaterThanOrEqualTo(0.45));
    expect(HSLColor.fromColor(palette.bg).lightness, lessThan(0.2));
  });
}
