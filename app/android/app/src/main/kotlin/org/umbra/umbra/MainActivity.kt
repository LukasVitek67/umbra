package org.umbra.umbra

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * NullChat's Android entry point.
 *
 * The only job beyond the standard Flutter activity is telling the app where
 * the native library folder is. Android refuses to execute a file the app wrote
 * itself (W^X since API 29), so the bundled `tor` ships as `libtor.so` inside
 * the APK and is started from there — and only the Java side knows that path.
 */
class MainActivity : FlutterActivity() {
    private val channelName = "org.umbra/native"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "nativeLibraryDir" -> result.success(applicationInfo.nativeLibraryDir)
                    else -> result.notImplemented()
                }
            }
    }
}
