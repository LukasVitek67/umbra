// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One NullChat at a time.
//
// Every instance starts its own Tor over the same account directory, and Tor
// refuses to share it: the first one holds the lock and the others sit there
// bootstrapping forever ("Tor did not connect in 900 s"). The same duplicates
// hold nullchat.exe open, so an update cannot swap the files either. Both problems
// disappear once a second launch simply hands over to the first.
//
// The lock is a file lock (the OS drops it if we crash, so no stale-lockfile
// dance) plus a tiny loopback socket, so the second launch can say "show
// yourself" before exiting.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'app_dir.dart';

import 'package:ffi/ffi.dart';

// Windows' own single-instance mechanism, bound directly: a named mutex is
// three calls, and the win32 package does not expose them.
final DynamicLibrary _kernel32 =
    Platform.isWindows ? DynamicLibrary.open('kernel32.dll') : DynamicLibrary.process();

final int Function(Pointer<Void>, int, Pointer<Utf16>) _createMutex = _kernel32.lookupFunction<
    IntPtr Function(Pointer<Void>, Int32, Pointer<Utf16>),
    int Function(Pointer<Void>, int, Pointer<Utf16>)>('CreateMutexW');

/// Opening tells us whether someone already claimed the name. `GetLastError`
/// would be the usual way, but through Dart's FFI the runtime can clobber the
/// thread's last-error value before we read it — asking directly cannot lie.
final int Function(int, int, Pointer<Utf16>) _openMutex = _kernel32.lookupFunction<
    IntPtr Function(Uint32, Int32, Pointer<Utf16>),
    int Function(int, int, Pointer<Utf16>)>('OpenMutexW');

/// `SYNCHRONIZE` — the least we can ask for and still get a handle.
const int _synchronize = 0x00100000;

final int Function(int) _closeHandle =
    _kernel32.lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');

final int Function(int) _releaseMutex =
    _kernel32.lookupFunction<Int32 Function(IntPtr), int Function(int)>('ReleaseMutex');


class SingleInstance {
  static RandomAccessFile? _lock;
  static ServerSocket? _server;

  /// True when this process may continue. False means another NullChat is already
  /// running (it has been asked to come to the front) and we should quit.
  static Future<bool> acquire({required Future<void> Function() onSecondLaunch}) async {
    if (!Platform.isWindows && !Platform.isLinux && !Platform.isMacOS) return true;
    try {
      final dir = Directory(await AppDir.path());
      final sep = Platform.pathSeparator;
      final lockFile = File('${dir.path}${sep}instance.lock');
      final portFile = File('${dir.path}${sep}instance.port');

      final claimed = _claim(lockFile);
      _note(claimed ? 'this process is the running NullChat' : 'another NullChat is running — handing over');
      if (!claimed) {
        // Someone else is running: ask them to show their window, step aside.
        await _wakeExisting(portFile);
        return false;
      }

      // Listen for later launches. Port 0: the OS picks a free one and we write
      // it down for whoever comes next.
      _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      await portFile.writeAsString('${_server!.port}');
      _server!.listen((socket) async {
        socket.destroy();
        await onSecondLaunch();
      });
      return true;
    } catch (e) {
      // If any of this fails we would rather run than refuse to start — but
      // leave a trace, because a silent failure here brings back the "six
      // Umbras fighting over Tor" bug.
      _note('single-instance check failed: $e');
      return true;
    }
  }

  /// Take the "I am the running NullChat" claim, or report that someone else has
  /// it. Windows gets a named mutex — the mechanism the OS provides for exactly
  /// this; elsewhere a file lock does the same job.
  static bool _claim(File lockFile) {
    if (Platform.isWindows) {
      final name = r'Local\UmbraSingleInstance'.toNativeUtf16();
      try {
        final existing = _openMutex(_synchronize, 0, name);
        if (existing != 0) {
          _closeHandle(existing);
          return false;
        }
        final handle = _createMutex(nullptr, 1, name);
        if (handle == 0) return true; // cannot tell: let the app run
        _mutex = handle;
        return true;
      } finally {
        calloc.free(name);
      }
    }
    try {
      final raf = lockFile.openSync(mode: FileMode.write);
      // An explicit one-byte range, not the whole file: an empty file locks a
      // zero-length range, which succeeds for everyone.
      raf.lockSync(FileLock.exclusive, 0, 1);
      _lock = raf;
      return true;
    } on FileSystemException {
      return false;
    }
  }

  static int? _mutex;

  /// A line in the app's log directory; the only way to see why a second launch
  /// behaved the way it did, since it has no window to report from.
  static void _note(String message) {
    try {
      final dir = Directory(
        '${Platform.environment['APPDATA']}${Platform.pathSeparator}org.umbra${Platform.pathSeparator}nullchat',
      );
      if (!dir.existsSync()) return;
      File('${dir.path}${Platform.pathSeparator}instance.log')
          .writeAsStringSync('${DateTime.now().toIso8601String()} $message\n',
              mode: FileMode.append);
    } catch (_) {}
  }

  static Future<void> _wakeExisting(File portFile) async {
    try {
      final port = int.tryParse((await portFile.readAsString()).trim());
      if (port == null) return;
      final socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        port,
        timeout: const Duration(seconds: 2),
      );
      socket.add(utf8.encode('show'));
      await socket.flush();
      socket.destroy();
    } catch (_) {
      // The port file can be stale (a crash, a killed process). Nothing to do:
      // we are exiting anyway, and the next start will rewrite it.
    }
  }

  /// Release everything (only meaningful right before quitting).
  static Future<void> release() async {
    try {
      await _server?.close();
      await _lock?.unlock(0, 1);
      await _lock?.close();
      final mutex = _mutex;
      if (mutex != null) {
        _releaseMutex(mutex);
        _closeHandle(mutex);
      }
    } catch (_) {}
  }
}
