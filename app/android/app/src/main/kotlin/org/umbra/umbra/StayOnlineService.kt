package org.umbra.umbra

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps NullChat's process alive while the app is not on screen.
 *
 * ### Why a service at all
 *
 * The networking is not in Dart. Tor and the Rust transport run on their own
 * threads inside this process, and the keep-alive loop dials contacts and
 * empties the outbox on its own. What it cannot survive is Android reclaiming
 * the process, which happens within seconds of leaving an app that has no
 * foreground service. Nothing here talks to the network; it exists so that the
 * part which does is allowed to keep running.
 *
 * ### What it shows
 *
 * A permanent notification, because Android requires one and because a program
 * that stays online in the background should say so rather than hide it. Its
 * text says the app is connected and nothing else: not who wrote, not how many
 * are waiting. A notification is drawn by the system, kept in its own store,
 * and readable from the lock screen — everything the duress passphrases exist
 * to make deniable would be undone by putting content in it.
 *
 * ### START_STICKY
 *
 * If Android kills the process under memory pressure it starts the service
 * again with a null intent. That is the honest behaviour for something the user
 * asked to stay reachable — but the sign-in state is gone with the process, so
 * the restarted service holds nothing open until the app is opened again. It is
 * a placeholder that keeps the notification honest, not a claim of delivery.
 */
class StayOnlineService : Service() {

    companion object {
        private const val CHANNEL_ID = "nullchat.online"
        private const val NOTIFICATION_ID = 1

        fun start(context: Context) {
            val intent = Intent(context, StayOnlineService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, StayOnlineService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    /**
     * Swiping the app away is not "stop being reachable". The task is gone, the
     * service is not, which is exactly what the user asked for by turning this
     * on — and what they turn off in Settings when they do not want it.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.online_channel_name),
            // Low: it belongs in the shade, not in the user's face, and it must
            // never make a sound — it says nothing worth being interrupted for.
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.online_channel_description)
            setShowBadge(false)
            enableVibration(false)
            enableLights(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.online_title))
            .setContentText(getString(R.string.online_text))
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(open)
            .setOngoing(true)
            // Nothing here is private, but say so explicitly rather than let a
            // future change to the text quietly appear on a locked screen.
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
    }
}
