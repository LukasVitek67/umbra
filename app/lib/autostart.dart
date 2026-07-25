// SPDX-License-Identifier: AGPL-3.0-or-later
//
// "Start with Windows" — a per-user Run entry. We shell out to reg.exe instead
// of pulling in a registry package: it touches only the current user's hive,
// needs no admin rights, and the user can undo it by hand if they ever want to.

import 'dart:io';

class Autostart {
  static const _key = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const _valueName = 'Umbra';

  static bool get supported => Platform.isWindows;

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
              '"${Platform.resolvedExecutable}"',
              '/f',
            ])
          : await Process.run('reg.exe', ['delete', _key, '/v', _valueName, '/f']);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
