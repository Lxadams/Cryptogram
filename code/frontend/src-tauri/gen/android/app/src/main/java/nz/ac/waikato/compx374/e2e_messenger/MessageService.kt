package nz.ac.waikato.compx374.e2e_messenger

import android.Manifest
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * Foreground service that runs while someone is logged in (started and
 * stopped by [NativeBridge]). It does no work itself: its only job is to
 * keep the app's process running with foreground priority, so Android
 * doesn't freeze or kill it in the background and the Rust backend keeps
 * receiving messages over its UDP socket. Android requires an ongoing
 * notification while it runs.
 *
 * It also owns the app's notifications, including the one for new messages.
 */
class MessageService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createChannels(this)
        val notification = NotificationCompat.Builder(this, CHANNEL_CONNECTION)
            .setSmallIcon(R.drawable.ic_stat_message)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.connection_notification_text))
            .setContentIntent(openAppIntent(this))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, ID_CONNECTION, notification, type)
        // Not restarted if Android kills the process: nobody can be logged in
        // again without their passcode, and the relay holds messages until then.
        return START_NOT_STICKY
    }

    companion object {
        private const val TAG = "MessageService"
        private const val CHANNEL_CONNECTION = "connection"
        private const val CHANNEL_MESSAGES = "messages"
        private const val ID_CONNECTION = 1
        private const val ID_MESSAGES = 2

        /** Messages notified since the user last opened the app. */
        private var unread = 0

        fun start(context: Context) {
            try {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, MessageService::class.java),
                )
            } catch (e: Exception) {
                // e.g. Android refusing to start it while the app is in the
                // background. Messages then arrive while the app is open.
                Log.w(TAG, "Couldn't start the background service", e)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, MessageService::class.java))
            clearMessageNotifications(context)
        }

        /**
         * Shows (or updates) the new-message notification. It names the
         * sender but never shows message text, so nothing readable ends up
         * on the lock screen.
         */
        fun notifyMessage(context: Context, from: String) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                return
            }
            createChannels(context)
            unread += 1
            val title = if (unread == 1) {
                context.getString(R.string.message_notification_title_one)
            } else {
                context.getString(R.string.message_notification_title_many, unread)
            }
            val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
                .setSmallIcon(R.drawable.ic_stat_message)
                .setContentTitle(title)
                .setContentText(context.getString(R.string.message_notification_text, from))
                .setContentIntent(openAppIntent(context))
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setNumber(unread)
                .build()
            NotificationManagerCompat.from(context).notify(ID_MESSAGES, notification)
        }

        fun clearMessageNotifications(context: Context) {
            unread = 0
            NotificationManagerCompat.from(context).cancel(ID_MESSAGES)
        }

        private fun createChannels(context: Context) {
            val manager = NotificationManagerCompat.from(context)
            manager.createNotificationChannel(
                NotificationChannelCompat.Builder(CHANNEL_MESSAGES, NotificationManagerCompat.IMPORTANCE_HIGH)
                    .setName(context.getString(R.string.channel_messages))
                    .build(),
            )
            manager.createNotificationChannel(
                NotificationChannelCompat.Builder(CHANNEL_CONNECTION, NotificationManagerCompat.IMPORTANCE_MIN)
                    .setName(context.getString(R.string.channel_connection))
                    .setDescription(context.getString(R.string.channel_connection_description))
                    .build(),
            )
        }

        /** Brings the app's existing task to the front, like tapping its icon. */
        private fun openAppIntent(context: Context): PendingIntent {
            val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
                ?: Intent(context, MainActivity::class.java)
            return PendingIntent.getActivity(
                context,
                0,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
    }
}
