// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Duress passphrases: a second (and third) way into the account that does
// something other than show the real thing.
//
// The screen is deliberately wordy where it matters. A feature like this is
// only worth having if the person using it knows precisely where it stops
// working, and the situations it exists for are the ones where being wrong is
// expensive. So the limits are on the screen, not in a manual nobody opens.

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

void showDuressScreen(BuildContext context) {
  showDialog<void>(
    context: context,
    builder: (ctx) => const _DuressDialog(),
  );
}

class _DuressDialog extends StatelessWidget {
  const _DuressDialog();

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final set = appState.duressConfigured;
        return AlertDialog(
          backgroundColor: UmbraColors.surfaceHigh,
          title: Text(L.t('duress.title')),
          content: SizedBox(
            width: 560,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(L.t('duress.intro'),
                      style: TextStyle(
                          color: UmbraColors.textMuted, fontSize: 13, height: 1.45)),
                  const SizedBox(height: 18),
                  _Option(
                    kind: 'decoy',
                    icon: Icons.theater_comedy_outlined,
                    title: L.t('duress.decoy.title'),
                    body: L.t('duress.decoy.body'),
                    configured: set.contains('decoy'),
                  ),
                  const SizedBox(height: 12),
                  _Option(
                    kind: 'wipe',
                    icon: Icons.local_fire_department_outlined,
                    title: L.t('duress.wipe.title'),
                    body: L.t('duress.wipe.body'),
                    configured: set.contains('wipe'),
                  ),
                  const SizedBox(height: 18),
                  // Not a footnote. What the operating system keeps is the most
                  // likely way any of this comes apart in practice.
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: UmbraColors.danger.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                          color: UmbraColors.danger.withValues(alpha: 0.35)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(Icons.warning_amber_rounded,
                                size: 16, color: UmbraColors.danger),
                            const SizedBox(width: 8),
                            Text(L.t('duress.limits.title'),
                                style: TextStyle(
                                    color: UmbraColors.danger,
                                    fontSize: 12,
                                    fontWeight: FontWeight.w700)),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(L.t('duress.limits.body'),
                            style: TextStyle(
                                color: UmbraColors.textMuted,
                                fontSize: 12,
                                height: 1.5)),
                      ],
                    ),
                  ),
                  if (set.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(Icons.notifications_off_outlined,
                            size: 16, color: UmbraColors.accent),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(L.t('duress.notifications'),
                              style: TextStyle(
                                  color: UmbraColors.accent,
                                  fontSize: 12,
                                  height: 1.45)),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(L.t('common.close')),
            ),
          ],
        );
      },
    );
  }
}

class _Option extends StatelessWidget {
  const _Option({
    required this.kind,
    required this.icon,
    required this.title,
    required this.body,
    required this.configured,
  });

  final String kind;
  final IconData icon;
  final String title;
  final String body;
  final bool configured;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: UmbraColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: UmbraColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: UmbraColors.accent),
              const SizedBox(width: 10),
              Expanded(
                child: Text(title,
                    style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
              ),
              if (configured)
                Text(L.t('duress.set'),
                    style: TextStyle(
                        color: UmbraColors.accent,
                        fontSize: 12,
                        fontWeight: FontWeight.w600)),
            ],
          ),
          const SizedBox(height: 8),
          Text(body,
              style: TextStyle(
                  color: UmbraColors.textMuted, fontSize: 12, height: 1.45)),
          const SizedBox(height: 12),
          Row(
            children: [
              if (!configured)
                FilledButton(
                  onPressed: () => _askPassphrase(context, kind),
                  child: Text(L.t('duress.setUp')),
                )
              else
                TextButton(
                  onPressed: () => _askRemoval(context),
                  child: Text(L.t('duress.remove'),
                      style: TextStyle(color: UmbraColors.danger)),
                ),
              if (kind == 'decoy' && configured) ...[
                const SizedBox(width: 8),
                TextButton(
                  onPressed: () => _askFiller(context),
                  child: Text(L.t('duress.fill')),
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }
}

/// Ask for the new duress passphrase, twice, and refuse the obvious mistakes.
Future<void> _askPassphrase(BuildContext context, String kind) async {
  final first = TextEditingController();
  final again = TextEditingController();
  String? error;
  await showDialog<void>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(kind == 'decoy'
            ? L.t('duress.decoy.title')
            : L.t('duress.wipe.title')),
        content: SizedBox(
          width: 420,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(L.t('duress.pickHint'),
                  style: TextStyle(
                      color: UmbraColors.textMuted, fontSize: 12, height: 1.45)),
              const SizedBox(height: 14),
              TextField(
                controller: first,
                obscureText: true,
                autofocus: true,
                decoration: InputDecoration(labelText: L.t('duress.newPhrase')),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: again,
                obscureText: true,
                decoration: InputDecoration(labelText: L.t('duress.repeat')),
              ),
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!,
                    style: TextStyle(color: UmbraColors.danger, fontSize: 12)),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(L.t('common.cancel')),
          ),
          FilledButton(
            onPressed: () {
              if (first.text != again.text) {
                setLocal(() => error = L.t('duress.mismatch'));
                return;
              }
              final failed = appState.setDuressPassphrase(kind, first.text);
              if (failed != null) {
                setLocal(() => error = failed);
                return;
              }
              Navigator.of(ctx).pop();
            },
            child: Text(L.t('common.save')),
          ),
        ],
      ),
    ),
  );
}

/// Removing one needs the passphrase itself — nothing else can reach its rows.
Future<void> _askRemoval(BuildContext context) async {
  final field = TextEditingController();
  String? error;
  await showDialog<void>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('duress.remove')),
        content: SizedBox(
          width: 420,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(L.t('duress.removeHint'),
                  style: TextStyle(
                      color: UmbraColors.textMuted, fontSize: 12, height: 1.45)),
              const SizedBox(height: 14),
              TextField(
                controller: field,
                obscureText: true,
                autofocus: true,
                decoration: InputDecoration(labelText: L.t('duress.thatPhrase')),
              ),
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!,
                    style: TextStyle(color: UmbraColors.danger, fontSize: 12)),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(L.t('common.cancel')),
          ),
          FilledButton(
            onPressed: () {
              final failed = appState.clearDuressPassphrase(field.text);
              if (failed != null) {
                setLocal(() => error = failed);
                return;
              }
              Navigator.of(ctx).pop();
            },
            child: Text(L.t('duress.remove')),
          ),
        ],
      ),
    ),
  );
}

/// Put a conversation into the decoy account, so it is not suspiciously empty.
Future<void> _askFiller(BuildContext context) async {
  final phrase = TextEditingController();
  final who = TextEditingController();
  final text = TextEditingController();
  String? error;
  String? done;
  await showDialog<void>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('duress.fill')),
        content: SizedBox(
          width: 480,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(L.t('duress.fillHint'),
                    style: TextStyle(
                        color: UmbraColors.textMuted, fontSize: 12, height: 1.45)),
                const SizedBox(height: 14),
                TextField(
                  controller: phrase,
                  obscureText: true,
                  decoration: InputDecoration(labelText: L.t('duress.decoyPhrase')),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: who,
                  decoration: InputDecoration(labelText: L.t('duress.fillWho')),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: text,
                  minLines: 5,
                  maxLines: 10,
                  decoration: InputDecoration(
                    labelText: L.t('duress.fillLines'),
                    alignLabelWithHint: true,
                  ),
                ),
                if (error != null) ...[
                  const SizedBox(height: 10),
                  Text(error!,
                      style: TextStyle(color: UmbraColors.danger, fontSize: 12)),
                ],
                if (done != null) ...[
                  const SizedBox(height: 10),
                  Text(done!,
                      style: TextStyle(color: UmbraColors.accent, fontSize: 12)),
                ],
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(L.t('common.close')),
          ),
          FilledButton(
            onPressed: () {
              final lines = text.text
                  .split('\n')
                  .map((l) => l.trim())
                  .where((l) => l.isNotEmpty)
                  .toList();
              if (lines.isEmpty || who.text.trim().isEmpty) {
                setLocal(() => error = L.t('duress.fillEmpty'));
                return;
              }
              final failed =
                  appState.fillDecoy(phrase.text, who.text, lines);
              setLocal(() {
                error = failed;
                if (failed == null) {
                  done = L.t('duress.fillDone')
                      .replaceAll('{n}', lines.length.toString());
                  who.clear();
                  text.clear();
                }
              });
            },
            child: Text(L.t('common.save')),
          ),
        ],
      ),
    ),
  );
}
