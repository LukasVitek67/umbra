// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The gate a user sees right after unlocking: Umbra cannot do anything useful
// until Tor is up, so instead of a dead-looking chat list we show what is
// happening and roughly how far along it is.

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

class ConnectingScreen extends StatelessWidget {
  const ConnectingScreen({super.key});

  /// Rough progress from Tor's own bootstrap messages ("Bootstrapped 45% …").
  double? _progress(String status) {
    final m = RegExp(r'Bootstrapped (\d+)%').firstMatch(status);
    if (m == null) return null;
    return int.parse(m.group(1)!) / 100.0;
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final status = appState.netStatus;
        final progress = _progress(status);
        final failed = appState.lastError != null && progress == null;

        return Scaffold(
          body: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Center(child: _PulsingMark()),
                    const SizedBox(height: 28),
                    Text(
                      L.t('connecting.title'),
                      textAlign: TextAlign.center,
                      style: Theme.of(context)
                          .textTheme
                          .headlineMedium
                          ?.copyWith(fontSize: 24),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      L.t('connecting.subtitle'),
                      textAlign: TextAlign.center,
                      style: TextStyle(
                          color: UmbraColors.textMuted, fontSize: 13, height: 1.45),
                    ),
                    const SizedBox(height: 28),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(999),
                      child: LinearProgressIndicator(
                        value: progress,
                        minHeight: 6,
                        backgroundColor: UmbraColors.surfaceHigh,
                        valueColor: AlwaysStoppedAnimation(
                            failed ? UmbraColors.danger : UmbraColors.accent),
                      ),
                    ),
                    const SizedBox(height: 14),
                    Text(
                      status,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: failed ? UmbraColors.danger : UmbraColors.textMuted,
                        fontSize: 12,
                        height: 1.4,
                      ),
                    ),
                    if (failed) ...[
                      const SizedBox(height: 18),
                      // The app already repairs and retries by itself once; this
                      // is for the case where that was not enough, so the user
                      // is not left with a screen that only says "no".
                      FilledButton.icon(
                        onPressed: appState.repairTor,
                        icon: const Icon(Icons.healing, size: 18),
                        label: Text(L.t('connecting.repair')),
                      ),
                      const SizedBox(height: 8),
                      Text(L.t('connecting.repairHelp'),
                          textAlign: TextAlign.center,
                          style: TextStyle(
                              color: UmbraColors.textMuted, fontSize: 11, height: 1.4)),
                    ],
                    const SizedBox(height: 26),
                    Panel(
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(Icons.info_outline,
                              size: 16, color: UmbraColors.textMuted),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              L.t('connecting.hint'),
                              style: TextStyle(
                                  color: UmbraColors.textMuted,
                                  fontSize: 12,
                                  height: 1.45),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

/// The brand mark with a slow breathing glow, so the screen never looks frozen.
class _PulsingMark extends StatefulWidget {
  const _PulsingMark();

  @override
  State<_PulsingMark> createState() => _PulsingMarkState();
}

class _PulsingMarkState extends State<_PulsingMark>
    with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1800),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _c,
      builder: (context, _) {
        final t = Curves.easeInOut.transform(_c.value);
        return Container(
          width: 88,
          height: 88,
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1E2A2A), Color(0xFF102523)],
            ),
            borderRadius: BorderRadius.circular(26),
            border: Border.all(
                color: UmbraColors.accent.withValues(alpha: 0.35 + 0.35 * t)),
            boxShadow: [
              BoxShadow(
                color: UmbraColors.accent.withValues(alpha: 0.12 + 0.22 * t),
                blurRadius: 28 + 12 * t,
                spreadRadius: -4,
              ),
            ],
          ),
          child: Icon(Icons.shield_moon_rounded,
              size: 42, color: UmbraColors.accent.withValues(alpha: 0.75 + 0.25 * t)),
        );
      },
    );
  }
}
