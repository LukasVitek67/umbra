// SPDX-License-Identifier: AGPL-3.0-or-later
//
// "Start with Windows" — a per-user Run entry. We shell out to reg.exe instead
// of pulling in a registry package: it touches only the current user's hive,
// needs no admin rights, and the user can undo it by hand if they ever want to.

import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'background.dart';

class Autostart {
  static const _key = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const _valueName = 'Umbra';

  static bool get supported => Platform.isWindows;

  /// Turn auto-start on the first time Umbra runs on this computer.
  ///
  /// A messenger nobody can reach is not much of a messenger, so the default is
  /// "on" — but only as a starting point: the marker file means a user who
  /// switches it off in Settings is never overruled on the next start.
  static Future<void> enableByDefaultOnce() async {
    if (!supported) return;
    try {
      final dir = await getApplicationSupportDirectory();
      final marker = File('${dir.path}${Platform.pathSeparator}autostart.configured');
      if (await marker.exists()) return;
      await set(true);
      await marker.writeAsString('1');
    } catch (_) {
      // Never block startup on a convenience setting.
    }
  }

  /// True when Windows is set to launch this build at sign-in.
  static Future<bool> isEnabled() async {
    if (!supported) return false;
    try {
      final r = await Process.run('reg.exe', ['query', _key, '/v', _valueName]);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> set(bool enabled) async {
    if (!supported) return false;
    try {
      final r = enabled
          ? await Process.run('reg.exe', [
              'add',
              _key,
              '/v',
              _valueName,
              '/t',
              'REG_SZ',
              '/d',
              // Launched at sign-in it belongs in the tray, not on screen.
              '"${Platform.resolvedExecutable}" $kBackgroundFlag',
              '/f',
            ])
          : await Process.run('reg.exe', ['delete', _key, '/v', _valueName, '/f']);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
