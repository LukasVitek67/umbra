// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Where a remembered passphrase is kept, per platform.
//
// Automatic sign-in used to be Windows-only, because the Rust side knows one
// way to protect a secret from the operating system: DPAPI. Everywhere else it
// answered "cannot", and the option was hidden — which is not the same as the
// feature being impossible. Android has a secret store, and a better one:
//
//   * **Android** — EncryptedSharedPreferences under a key held in the Android
//     Keystore. On a device with a secure element the key is hardware-backed
//     and cannot be extracted at all, not even by this app, and the stored blob
//     is useless on any other device. DPAPI has no such property: anything
//     running as the Windows user can ask for the plaintext back.
//   * **Windows** — the DPAPI path in `accounts.rs`, untouched. It works, it is
//     bound to the account's own salt, and moving it would mean migrating every
//     existing entry for nothing.
//   * **Linux** — not yet. The Secret Service is the right home for it and
//     libsecret is already a dependency of the Linux package, but it needs its
//     own binding; until then the option is not offered there rather than
//     offered and quietly ignored.
//
// The Android side is a method channel into `MainActivity` rather than a
// package: every Flutter plugin that does this also ships a Windows
// implementation that needs Visual Studio's ATL headers, which the toolchain
// does not install — so the Windows build failed to compile a plugin it would
// never have called.
//
// What none of this changes: a passphrase a program can recover without the
// user present is one an attacker with that program's reach can recover too.
// Android narrows that the most; it does not close it. The text beside the
// checkbox says so, and says it differently per platform.

import 'dart:io';

import 'package:flutter/services.dart';

class PassphraseVault {
  PassphraseVault._();
  static final PassphraseVault instance = PassphraseVault._();

  static const _channel = MethodChannel('org.umbra/native');

  /// Whether the passphrase is kept by the platform rather than by Rust.
  bool get _viaPlatform => Platform.isAndroid;

  /// Can this device hold a passphrase for automatic sign-in at all?
  bool get available => Platform.isWindows || Platform.isAndroid;

  /// Which warning belongs beside the checkbox here.
  ///
  /// A single wording would be wrong somewhere: on Android other apps cannot
  /// read it, on Windows anything running as you can.
  String get warningKey =>
      Platform.isAndroid ? 'accounts.rememberHelpDevice' : 'accounts.rememberHelp';

  String _key(String accountId) => 'nullchat.passphrase.$accountId';

  /// Remember `passphrase` for `accountId`.
  ///
  /// Returns false when the platform refused, in which case nothing was stored
  /// and nothing should tell the user otherwise.
  Future<bool> store(String accountId, String passphrase) async {
    if (!_viaPlatform) return false; // Windows stores it inside `openAccount`
    try {
      final ok = await _channel.invokeMethod<bool>(
        'secretWrite',
        {'key': _key(accountId), 'value': passphrase},
      );
      return ok ?? false;
    } catch (_) {
      return false;
    }
  }

  /// The passphrase remembered for `accountId`, or null to ask for it.
  Future<String?> read(String accountId) async {
    if (!_viaPlatform) return null; // Windows recovers it in `openAccountAuto`
    try {
      final value = await _channel.invokeMethod<String>(
        'secretRead',
        {'key': _key(accountId)},
      );
      return (value == null || value.isEmpty) ? null : value;
    } catch (_) {
      return null;
    }
  }

  /// Forget it — when automatic sign-in is turned off, and when an account is
  /// deleted, so nothing outlives what it opened.
  Future<void> clear(String accountId) async {
    if (!_viaPlatform) return; // Windows: `setAutologin(false)` clears it there
    try {
      await _channel.invokeMethod<bool>('secretDelete', {'key': _key(accountId)});
    } catch (_) {}
  }
}
