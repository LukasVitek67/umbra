// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Where a remembered passphrase is kept, per platform.
//
// Automatic sign-in was Windows-only because the Rust side knows one way to
// protect a secret against the operating system: DPAPI. Everywhere else it
// returned "cannot", and the option was hidden — which is not the same as the
// feature being impossible. Both other platforms we ship to have a real secret
// store, and on Android it is better than the one Windows offers:
//
//   * **Android** — EncryptedSharedPreferences under a key held in the Android
//     Keystore. The key is hardware-backed where the device has a TEE or secure
//     element, and cannot be extracted even by code running as this app. DPAPI
//     has no equivalent property: anything running as the Windows user can ask
//     for the plaintext back.
//   * **Linux** — the Secret Service (gnome-keyring, KWallet). Locked with the
//     login keyring, so it is protected while the session is locked.
//   * **Windows** — the existing DPAPI path in `accounts.rs`, left alone. It
//     works, it is already bound to the account's own salt, and moving it would
//     mean migrating every entry for no gain.
//
// What none of them change: a passphrase that a program can recover without the
// user is a passphrase an attacker with that program's privileges can recover
// too. Android narrows this most (the key never leaves the Keystore, and the
// blob is useless off the device); it does not close it. The warning next to
// the checkbox still applies, and still says so.

import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class PassphraseVault {
  PassphraseVault._();
  static final PassphraseVault instance = PassphraseVault._();

  static const _store = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  /// Windows keeps its own arrangement; see the note at the top.
  bool get _useOsStore => !Platform.isWindows;

  /// Can this system hold a passphrase at all?
  ///
  /// Everywhere we ship, now. Kept as a question rather than a constant because
  /// the answer is a property of the platform, and a build for one without a
  /// secret store should say no rather than pretend.
  bool get available =>
      Platform.isWindows ||
      Platform.isAndroid ||
      Platform.isLinux ||
      Platform.isMacOS;

  /// Which warning belongs next to the checkbox on this platform.
  ///
  /// The honest text is not the same everywhere, and a single wording would be
  /// wrong somewhere. On Android the key never leaves the Keystore, so another
  /// app cannot ask for the passphrase back; on Windows and Linux anything
  /// running as you can.
  String get warningKey =>
      Platform.isAndroid ? 'accounts.rememberHelpDevice' : 'accounts.rememberHelp';

  String _key(String accountId) => 'nullchat.passphrase.$accountId';

  /// Remember `passphrase` for `accountId`. Returns false if the platform
  /// refused, in which case nothing was stored and nothing should claim it was.
  Future<bool> store(String accountId, String passphrase) async {
    // Windows never reaches the vault: the Rust side already protects the
    // passphrase with DPAPI as part of signing in, and `read` there returns
    // null so `openAccountAuto` stays the way in.
    if (!_useOsStore) return false;
    try {
      await _store.write(key: _key(accountId), value: passphrase);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The passphrase remembered for `accountId`, or null.
  Future<String?> read(String accountId) async {
    if (!_useOsStore) return null; // Windows recovers it inside `openAccountAuto`
    try {
      final value = await _store.read(key: _key(accountId));
      return (value == null || value.isEmpty) ? null : value;
    } catch (_) {
      // A locked keyring, a device whose Keystore was reset by a factory
      // restore — both mean "ask for the passphrase", not "fail".
      return null;
    }
  }

  /// Forget it. Called when automatic sign-in is turned off and when an account
  /// is deleted, so nothing outlives the thing it belonged to.
  Future<void> clear(String accountId) async {
    if (!_useOsStore) return; // Windows: `setAutologin(false)` clears it there
    try {
      await _store.delete(key: _key(accountId));
    } catch (_) {}
  }
}
