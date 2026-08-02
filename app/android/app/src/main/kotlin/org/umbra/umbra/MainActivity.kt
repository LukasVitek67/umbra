package org.umbra.umbra

import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * NullChat's Android entry point.
 *
 * Two jobs beyond the standard Flutter activity.
 *
 * The first is telling the app where the native library folder is. Android
 * refuses to execute a file the app wrote itself (W^X since API 29), so the
 * bundled `tor` ships as `libtor.so` inside the APK and is started from there —
 * and only the Java side knows that path.
 *
 * The second is holding a remembered passphrase. This is done here rather than
 * with a plugin because the plugins that do it drag in a Windows implementation
 * that needs Visual Studio's ATL headers, and the Windows build has no use for
 * it: there the passphrase is protected by DPAPI in `accounts.rs`. What Android
 * offers is better than DPAPI anyway — the key lives in the Keystore and is
 * hardware-backed on a device with a secure element, so it cannot be extracted
 * even by this app, and the stored blob is useless on any other device.
 */
class MainActivity : FlutterActivity() {
    private val channelName = "org.umbra/native"

    /**
     * Created on first use, not at startup: it touches the Keystore, and an
     * account that never asked to be remembered should not pay for it.
     */
    private val secrets: SharedPreferences by lazy {
        val master = MasterKey.Builder(applicationContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            applicationContext,
            "nullchat.secrets",
            master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "nativeLibraryDir" -> result.success(applicationInfo.nativeLibraryDir)

                    "secretWrite" -> runCatching {
                        val key = call.argument<String>("key")!!
                        val value = call.argument<String>("value")!!
                        secrets.edit().putString(key, value).commit()
                    }.fold({ result.success(it) }, { result.success(false) })

                    // A Keystore that will not open — a factory restore, a
                    // device whose lock screen was removed — means "ask for the
                    // passphrase", not "fail". Null says exactly that.
                    "secretRead" -> runCatching {
                        secrets.getString(call.argument<String>("key")!!, null)
                    }.fold({ result.success(it) }, { result.success(null) })

                    "secretDelete" -> runCatching {
                        secrets.edit().remove(call.argument<String>("key")!!).commit()
                    }.fold({ result.success(true) }, { result.success(false) })

                    else -> result.notImplemented()
                }
            }
    }
}
