// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Desktop notifications for incoming messages.
//
// What a notification says is a privacy decision, not a formatting one: it is
// text that appears on a screen the user may not be sitting at. So the default
// says only that something arrived, and for which account:
//
//     "New message on @lukas"
//
// The full form — sender, account and the message itself — is opt-in, and only
// for accounts that sign in automatically. The reasoning is simple: an account
// whose passphrase this computer remembers is one the user has already declared
// safe to open unattended. An account that asks for a passphrase every time is
// exactly the opposite declaration, and showing its messages on a locked-away
// screen would undo it. Hence the switch is greyed out there, with the reason
// written next to it rather than left to guess.

import 'dart:io';

import 'package:local_notifier/local_notifier.dart';
import 'package:path_provider/path_provider.dart';

import 'l10n.dart';

class Notifications {
  static bool _ready = false;
  static File? _prefFile;

  /// Which conversation is open right now (contact hex or group id), so we can
  /// stay quiet about it.
  static String? openConversation;

  /// True while the app window has focus.
  static bool windowFocused = true;

  /// Show sender + account + text instead of just "new message". Only ever true
  /// for an account that signs in automatically.
  static bool showContent = false;

  static bool get supported => Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  static Future<void> init() async {
    if (!supported || _ready) return;
    try {
      await localNotifier.setup(appName: 'Umbra');
      _ready = true;
    } catch (_) {
      // A missing notification service must never stop the messenger.
    }
    await _loadPreference();
  }

  static Future<void> _loadPreference() async {
    try {
      final dir = await getApplicationSupportDirectory();
      _prefFile = File('${dir.path}${Platform.pathSeparator}notification-preview.txt');
      if (await _prefFile!.exists()) {
        showContent = (await _prefFile!.readAsString()).trim() == '1';
      }
    } catch (_) {}
  }

  /// Turn the detailed form on or off (the caller checks that the account is
  /// allowed to).
  static Future<void> setShowContent(bool value) async {
    showContent = value;
    try {
      await _prefFile?.writeAsString(value ? '1' : '0');
    } catch (_) {}
  }

  /// Show a message notification unless the user is already looking at it.
  ///
  /// [detailed] is what the account allows; [preview] is whether this
  /// particular message may be quoted at all (a stranger's cannot).
  static Future<void> message({
    required String conversationId,
    required String account,
    required String from,
    required String body,
    required bool detailed,
    bool preview = true,
  }) async {
    if (!_ready) return;
    if (windowFocused && openConversation == conversationId) return;
    try {
      final n = detailed && preview
          ? LocalNotification(
              title: '$from → @$account',
              body: body,
            )
          : LocalNotification(
              title: L.t('notif.newFor').replaceAll('{account}', account),
              body: '',
            );
      await n.show();
    } catch (_) {}
  }
}
