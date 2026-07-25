// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Desktop notifications for incoming messages, in the spirit of any other
// messenger: a line in the corner when a message arrives while you are looking
// somewhere else.
//
// Two deliberate limits:
//   * nothing pops up for a chat you are already reading, or while the window
//     has focus — a notification for what is on screen is just noise;
//   * a message from someone waiting for approval shows *that* it arrived, not
//     what it says, so a stranger cannot put text on your screen.

import 'dart:io';

import 'package:local_notifier/local_notifier.dart';

import 'l10n.dart';

class Notifications {
  static bool _ready = false;

  /// Which conversation is open right now (contact hex or group id), so we can
  /// stay quiet about it.
  static String? openConversation;

  /// True while the app window has focus.
  static bool windowFocused = true;

  static bool get supported => Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  static Future<void> init() async {
    if (!supported || _ready) return;
    try {
      await localNotifier.setup(appName: 'Umbra');
      _ready = true;
    } catch (_) {
      // A missing notification service must never stop the messenger.
    }
  }

  /// Show a message notification unless the user is already looking at it.
  static Future<void> message({
    required String conversationId,
    required String from,
    required String body,
    bool preview = true,
  }) async {
    if (!_ready) return;
    if (windowFocused && openConversation == conversationId) return;
    try {
      final n = LocalNotification(
        title: from.isEmpty ? L.t('notif.message') : from,
        body: preview ? body : L.t('notif.message'),
      );
      await n.show();
    } catch (_) {}
  }
}
