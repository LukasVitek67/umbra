// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Staying reachable on a phone while the app is not on screen.
//
// This is the single biggest reason a message "never arrived". There is no
// server: a message waits on the sender's device until both people are running
// at the same moment. On a desktop that happens by itself — the app sits in the
// tray. On Android the process is reclaimed within seconds of leaving the app,
// Tor stops, the onion service disappears, and nothing moves until the app is
// opened again.
//
// A foreground service keeps the process alive, which is all the Rust side
// needs: its keep-alive loop dials contacts and empties the outbox on its own
// threads. Android requires a permanent notification in exchange, and that is
// the right trade to make visibly rather than quietly — see StayOnlineService
// for why the notification says nothing about who wrote or how much is waiting.
//
// On by default, because a messenger that only works while you are looking at
// it is not doing its job. Off in one switch, because a permanent notification
// and a process that never sleeps are not everyone's idea of a good bargain.

import 'dart:io';

import 'package:flutter/services.dart';

import 'app_dir.dart';

class StayOnline {
  StayOnline._();
  static final StayOnline instance = StayOnline._();

  static const _channel = MethodChannel('org.umbra/native');

  /// Only Android reclaims the process this way. The desktop has the tray.
  bool get supported => Platform.isAndroid;

  /// Where the user's answer is kept. A file beside the other preferences,
  /// which is how this app stores settings that must survive without a
  /// database — the database needs a passphrase, and this is read at startup.
  Future<File> _file() async =>
      File('${await AppDir.path()}${Platform.pathSeparator}stay-online.txt');

  /// Whether it should run. **Default on**, which is why the absence of the
  /// file reads as `true`: someone who never touched the switch gets a
  /// messenger that works.
  Future<bool> enabled() async {
    if (!supported) return false;
    try {
      final f = await _file();
      if (!await f.exists()) return true;
      return (await f.readAsString()).trim() != '0';
    } catch (_) {
      return true;
    }
  }

  /// Whether it should come back after the phone restarts. Kept on the Android
  /// side too, because the boot receiver has to read it without Flutter.
  Future<bool> startsOnBoot() async {
    if (!supported) return false;
    try {
      return await _channel.invokeMethod<bool>('backgroundStartOnBoot') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Turn it on or off, now and for next time.
  Future<void> setEnabled(bool on) async {
    if (!supported) return;
    try {
      await (await _file()).writeAsString(on ? '1' : '0');
    } catch (_) {
      // A preference we could not write is still worth applying this run.
    }
    await _apply(on);
    // Coming back after a restart only makes sense while it is on at all.
    if (!on) await setStartOnBoot(false);
  }

  Future<void> setStartOnBoot(bool on) async {
    if (!supported) return;
    try {
      await _channel.invokeMethod<bool>('backgroundSetStartOnBoot', {'enabled': on});
    } catch (_) {}
  }

  /// Start or stop the service to match the stored preference.
  ///
  /// Called after signing in: before that there is no session to keep alive,
  /// and a notification saying "you are reachable" would be a lie.
  Future<void> applyStoredPreference() async {
    if (!supported) return;
    await _apply(await enabled());
  }

  /// Stop it, whatever the preference says. For signing out: the session is
  /// gone, so nothing is reachable and nothing should claim to be.
  Future<void> stop() async {
    if (!supported) return;
    await _apply(false);
  }

  Future<void> _apply(bool on) async {
    try {
      await _channel.invokeMethod<bool>(on ? 'backgroundStart' : 'backgroundStop');
    } catch (_) {}
  }
}
