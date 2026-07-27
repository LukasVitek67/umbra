// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Running quietly in the background, the way a messenger has to.
//
// A messenger that only works while its window is open is not a messenger: the
// other side can reach you exactly when you happen to be looking at the screen.
// So NullChat starts with Windows into the tray, keeps Tor and the onion service
// running there, and the window is just a view onto it — closing the window
// hides it instead of quitting. Quitting is an explicit choice in the tray menu
// (or from Settings), because after that nobody can deliver anything to you.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'l10n.dart';
import 'notifications.dart';
import 'single_instance.dart';

/// The flag the auto-start entry passes, so a launch at sign-in does not throw
/// a window in the user's face.
const kBackgroundFlag = '--background';

class BackgroundMode with WindowListener, TrayListener {
  BackgroundMode._();
  static final BackgroundMode instance = BackgroundMode._();

  static bool get supported => Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  bool _ready = false;

  /// Set up the window and the tray icon. `startHidden` comes from the command
  /// line: true when Windows started us at sign-in.
  static Future<void> init({required bool startHidden}) async {
    if (!supported) return;
    await windowManager.ensureInitialized();
    await windowManager.setPreventClose(true);
    windowManager.addListener(instance);
    trayManager.addListener(instance);
    instance._ready = true;

    await windowManager.waitUntilReadyToShow(
      const WindowOptions(
        size: Size(1280, 820),
        minimumSize: Size(720, 560),
        title: 'NullChat',
      ),
      () async {
        if (startHidden) {
          // Stay out of sight, but keep the app alive: Tor bootstraps and the
          // onion service goes up while the tray icon is all the user sees.
          // (The native runner already skipped showing the window; this makes
          // sure it also stays out of the taskbar.)
          await windowManager.hide();
          await windowManager.setSkipTaskbar(true);
        } else {
          await windowManager.show();
          await windowManager.focus();
        }
      },
    );

    await instance._setUpTray();

    if (startHidden) {
      // The engine shows the window again once it paints its first frame, so
      // the last word has to come after that frame — and once more shortly
      // after, because the plugin's own "ready to show" can land later still.
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        await instance.hide();
        await Future<void>.delayed(const Duration(milliseconds: 700));
        if (await windowManager.isVisible()) await instance.hide();
      });
    }
  }

  /// Whether the window is on screen right now.
  Future<bool> get visible async => _ready && await windowManager.isVisible();

  Future<void> _setUpTray() async {
    try {
      // A bundled asset, not a path into the source tree. The old value pointed
      // at `windows/runner/resources/app_icon.ico`, which exists only when
      // running from a checkout — in a release build there was nothing there,
      // which is why the tray entry had no icon at all.
      await trayManager.setIcon(
        Platform.isWindows ? 'assets/tray/tray.ico' : 'assets/tray/tray.png',
      );
      await trayManager.setToolTip('NullChat');
      await _refreshMenu();
    } catch (_) {
      // No tray (some Linux desktops): the app still runs, just without it.
    }
  }

  Future<void> _refreshMenu() async {
    await trayManager.setContextMenu(Menu(items: [
      MenuItem(key: 'show', label: L.t('tray.open')),
      MenuItem.separator(),
      MenuItem(key: 'quit', label: L.t('tray.quit')),
    ]));
  }

  /// Bring the window back from the tray.
  Future<void> show() async {
    if (!_ready) return;
    await windowManager.setSkipTaskbar(false);
    await windowManager.show();
    await windowManager.focus();
  }

  Future<void> hide() async {
    if (!_ready) return;
    await windowManager.hide();
    await windowManager.setSkipTaskbar(true);
  }

  /// Really quit — after this nothing can reach the user.
  Future<void> quit() async {
    await SingleInstance.release();
    await trayManager.destroy();
    await windowManager.setPreventClose(false);
    await windowManager.destroy();
    exit(0);
  }

  // --- window events ---

  @override
  void onWindowClose() {
    // The window is a view, not the app: closing it puts NullChat in the tray so
    // messages keep arriving.
    hide();
  }

  @override
  void onWindowFocus() => Notifications.windowFocused = true;

  @override
  void onWindowBlur() => Notifications.windowFocused = false;

  // --- tray events ---

  @override
  void onTrayIconMouseDown() => show();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'show':
        show();
        break;
      case 'quit':
        quit();
        break;
    }
  }
}
