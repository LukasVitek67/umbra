// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Where the bundled binaries live.
//
// Desktop builds keep `tor` next to the executable and find it themselves. On
// Android nothing the app writes may be executed, so `tor` travels inside the
// APK as `libtor.so` and only the Java side can say where that folder ended up;
// we ask once at startup and hand the path to the Rust transport.

import 'dart:io';

import 'package:flutter/services.dart';

import 'src/rust/api/umbra.dart';

const _channel = MethodChannel('org.umbra/native');

Future<void> locateBundledBinaries() async {
  if (!Platform.isAndroid) return;
  try {
    final dir = await _channel.invokeMethod<String>('nativeLibraryDir');
    if (dir != null && dir.isNotEmpty) setNativeDir(path: dir);
  } catch (_) {
    // Without this the network cannot start; the connecting screen already
    // reports that, and crashing here would only hide the reason.
  }
}
