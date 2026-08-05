package org.umbra.umbra

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts the background service again after the phone restarts.
 *
 * Only when the user asked for it. The flag is written by the app when the
 * switch in Settings is turned on, and read here without going near Flutter —
 * a boot receiver has seconds to do its work, and starting a Dart engine to
 * read one boolean would be both slow and fragile.
 *
 * What this does *not* do is sign in. The passphrase is not something a boot
 * receiver may have, and an app that unlocked itself on restart would undo the
 * point of having a passphrase at all. So after a restart NullChat is running
 * and reachable only once it has been opened and unlocked — unless automatic
 * sign-in is on, in which case opening it is all it takes.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_START_ON_BOOT, false)) return
        StayOnlineService.start(context)
    }

    companion object {
        const val PREFS = "nullchat.background"
        const val KEY_START_ON_BOOT = "startOnBoot"
    }
}
