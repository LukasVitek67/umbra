// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Where this app keeps its data — and why that is not simply whatever
// `getApplicationSupportDirectory()` returns today.
//
// That function derives its answer from the application's name, which changed
// when Umbra became NullChat. Taking the new answer at face value would point a
// updated installation at an empty folder: no identity, no contacts, no
// history — with the real data still sitting on disk under the old name, which
// is somehow worse than losing it, because everything looks deleted.
//
// So: if the old directory exists and has an account in it, that is the
// directory. Nothing is copied and nothing is migrated, because a move that
// fails halfway through costs someone their identity, and there is nothing here
// worth that risk. New installations get the new path and never see any of it.

import 'dart:io';

import 'package:path_provider/path_provider.dart';

class AppDir {
  static String? _cached;

  /// The directory holding accounts, settings and logs.
  static Future<String> path() async {
    final cached = _cached;
    if (cached != null) return cached;

    final current = (await getApplicationSupportDirectory()).path;
    final resolved = await _preferExisting(current);
    _cached = resolved;
    return resolved;
  }

  /// Prefer a pre-rename directory that actually contains an account.
  static Future<String> _preferExisting(String current) async {
    if (await _hasAccounts(current)) return current;

    for (final legacy in _legacyPaths()) {
      if (legacy != current && await _hasAccounts(legacy)) {
        return legacy;
      }
    }
    return current;
  }

  /// Does this directory hold a real installation, rather than just existing?
  static Future<bool> _hasAccounts(String dir) async {
    try {
      final accounts = Directory('$dir${Platform.pathSeparator}accounts');
      if (await accounts.exists() && !await accounts.list().isEmpty) return true;
      // Installations from before multiple accounts kept the database directly
      // in the root of the support directory.
      for (final name in ['umbra.db', 'nullchat.db', 'accounts.json']) {
        if (await File('$dir${Platform.pathSeparator}$name').exists()) return true;
      }
    } catch (_) {
      // An unreadable directory is not one we should adopt.
    }
    return false;
  }

  /// Places earlier versions used, newest first.
  static List<String> _legacyPaths() {
    final sep = Platform.pathSeparator;
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData == null) return const [];
      return ['$appData${sep}org.umbra${sep}umbra'];
    }
    if (Platform.isLinux) {
      final home = Platform.environment['HOME'];
      if (home == null) return const [];
      return [
        '$home$sep.local${sep}share${sep}umbra',
        '$home$sep.local${sep}share${sep}org.umbra',
      ];
    }
    // Android keeps the same applicationId across the rename precisely so this
    // problem does not arise there.
    return const [];
  }
}
