// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The account picker: several identities can live on one computer, each with
// its own keys, contacts and history. This is what you see on launch when more
// than one exists (or when none signs in automatically).

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'passphrase_vault.dart';
import 'src/rust/api/nullchat.dart';
import 'theme.dart';

class AccountPickerScreen extends StatefulWidget {
  const AccountPickerScreen({super.key});

  @override
  State<AccountPickerScreen> createState() => _AccountPickerScreenState();
}

class _AccountPickerScreenState extends State<AccountPickerScreen> {
  List<AccountView> _accounts = [];
  AccountView? _unlocking;
  final _pass = TextEditingController();
  bool _remember = false;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  @override
  void dispose() {
    _pass.dispose();
    super.dispose();
  }

  Future<void> _reload() async {
    final list = await appState.accounts();
    if (mounted) setState(() => _accounts = list);
  }

  Future<void> _pick(AccountView a) async {
    if (a.autologin) {
      setState(() => _busy = true);
      final ok = await appState.signInAuto(a.id);
      if (!ok && mounted) {
        setState(() {
          _busy = false;
          _unlocking = a; // stored passphrase unusable → ask for it
          _error = appState.lastError;
        });
      }
      return;
    }
    setState(() {
      _unlocking = a;
      _error = null;
      _pass.clear();
      _remember = false;
    });
  }

  Future<void> _unlock() async {
    final a = _unlocking;
    if (a == null || _pass.text.length < 8) return;
    setState(() => _busy = true);
    final ok = await appState.signIn(a.id, _pass.text, remember: _remember);
    if (!ok && mounted) {
      setState(() {
        _busy = false;
        _error = appState.lastError;
      });
    }
  }

  Future<void> _confirmForget(AccountView a) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('accounts.removeTitle')),
        content: Text(
          '"${a.name}" — ${L.t('accounts.removeBody')}',
          style: TextStyle(color: UmbraColors.textMuted, height: 1.4),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text(L.t('common.cancel'))),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: UmbraColors.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(L.t('accounts.remove')),
          ),
        ],
      ),
    );
    if (yes == true) {
      await appState.forgetAccount(a.id);
      await _reload();
      if (mounted) setState(() => _unlocking = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Center(child: UmbraMarkSmall()),
                const SizedBox(height: 20),
                Text(
                  _unlocking == null ? L.t('accounts.title') : _unlocking!.name,
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontSize: 26),
                ),
                const SizedBox(height: 8),
                Text(
                  _unlocking == null
                      ? L.t('accounts.subtitle')
                      : L.t('onboard.unlock.subtitle'),
                  textAlign: TextAlign.center,
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                ),
                const SizedBox(height: 24),
                if (_unlocking == null) ...[
                  for (final a in _accounts)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: InkWell(
                        borderRadius: BorderRadius.circular(16),
                        onTap: _busy ? null : () => _pick(a),
                        child: Panel(
                          child: Row(
                            children: [
                              CircleAvatar(
                                radius: 20,
                                backgroundColor: UmbraColors.surfaceHigh,
                                child: Text(
                                  a.name.isEmpty ? '?' : a.name.characters.first.toUpperCase(),
                                  style: TextStyle(
                                      color: UmbraColors.accent, fontWeight: FontWeight.w700),
                                ),
                              ),
                              const SizedBox(width: 14),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(a.name.isEmpty ? L.t('accounts.unnamed') : a.name,
                                        style: const TextStyle(
                                            fontWeight: FontWeight.w600, fontSize: 15)),
                                    const SizedBox(height: 2),
                                    Text(
                                      a.autologin
                                          ? L.t('accounts.autoOn')
                                          : L.t('accounts.autoOff'),
                                      style: TextStyle(
                                          color: UmbraColors.textMuted, fontSize: 12),
                                    ),
                                  ],
                                ),
                              ),
                              IconButton(
                                tooltip: L.t('accounts.remove'),
                                icon: Icon(Icons.delete_outline,
                                    size: 18, color: UmbraColors.textMuted),
                                onPressed: _busy ? null : () => _confirmForget(a),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  const SizedBox(height: 6),
                  OutlinedButton.icon(
                    onPressed: _busy ? null : () => appState.startNewAccountFlow(),
                    icon: const Icon(Icons.person_add_alt, size: 18),
                    label: Text(L.t('accounts.add')),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: UmbraColors.accent,
                      side: BorderSide(color: UmbraColors.border),
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                ] else ...[
                  TextField(
                    controller: _pass,
                    obscureText: true,
                    autofocus: true,
                    // Without this the field never rebuilds the screen, so the
                    // button below keeps the answer it computed when the field
                    // was empty: disabled. It came alive only when something
                    // *else* called setState — ticking "sign in automatically"
                    // did it, which is why that looked like a requirement.
                    onChanged: (_) => setState(() {}),
                    onSubmitted: (_) => _unlock(),
                    decoration: InputDecoration(
                      hintText: L.t('onboard.passphrase'),
                      prefixIcon: Icon(Icons.lock_outline, color: UmbraColors.textMuted),
                    ),
                  ),
                  const SizedBox(height: 8),
                  if (appState.canRememberPassphrase)
                  CheckboxListTile(
                    value: _remember,
                    onChanged: (v) => setState(() => _remember = v ?? false),
                    controlAffinity: ListTileControlAffinity.leading,
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    title: Text(L.t('accounts.remember'),
                        style: TextStyle(fontSize: 13, color: UmbraColors.textPrimary)),
                    subtitle: Text(L.t(PassphraseVault.instance.warningKey),
                        style: TextStyle(fontSize: 11, color: UmbraColors.textMuted)),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 6),
                    Text(_error!,
                        style: TextStyle(color: UmbraColors.danger, fontSize: 12)),
                  ],
                  const SizedBox(height: 12),
                  FilledButton(
                    onPressed: (_pass.text.length >= 8 && !_busy) ? _unlock : null,
                    child: _busy
                        ? SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: UmbraColors.accentInk))
                        : Text(L.t('onboard.unlock.button')),
                  ),
                  TextButton(
                    onPressed: _busy ? null : () => setState(() => _unlocking = null),
                    child: Text(L.t('accounts.back')),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Small brand mark reused by the picker.
class UmbraMarkSmall extends StatelessWidget {
  const UmbraMarkSmall({super.key});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 64,
      height: 64,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(14),
        child: Image.asset('assets/logo.png', fit: BoxFit.cover),
      ),
    );
  }
}
