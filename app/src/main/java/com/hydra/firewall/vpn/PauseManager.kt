package com.hydra.firewall.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Temporary pause of the firewall ("Pause 15 min / 1 h"). The VPN is stopped like a normal user stop (so it is not
 * reported as an unexpected stop) and an alarm brings it back. If Android does not let the alarm start the service,
 * Hydra posts a notification and resumes as soon as the app is opened.
 */
object PauseManager {
    const val ACTION_PAUSE_END = "com.hydra.firewall.action.PAUSE_END"
    private const val PREFS = "hydra_pause"
    private const val KEY_UNTIL = "until"
    private const val REQUEST_CODE = 9455

    /** Milliseconds left of a pause that ends at [until] (0 when there is none or it already ended). */
    internal fun remaining(until: Long, now: Long): Long = if (until <= 0L) 0L else (until - now).coerceAtLeast(0L)

    /** "mm:ss" (rounded up), e.g. 899_000 -> "15:00" - 1 s... used by the Home countdown. */
    internal fun formatRemaining(ms: Long): String {
        val totalSeconds = ((ms.coerceAtLeast(0L) + 999L) / 1000L)
        return String.format(java.util.Locale.US, "%d:%02d", totalSeconds / 60L, totalSeconds % 60L)
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun remainingMs(context: Context): Long = remaining(prefs(context).getLong(KEY_UNTIL, 0L), System.currentTimeMillis())

    fun isPaused(context: Context): Boolean = remainingMs(context) > 0L

    fun pause(context: Context, minutes: Int) {
        val app = context.applicationContext
        val until = System.currentTimeMillis() + minutes.coerceIn(1, 24 * 60) * 60_000L
        prefs(app).edit().putLong(KEY_UNTIL, until).apply()
        schedule(app, until)
        app.startService(Intent(app, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_STOP })
    }

    /** Forget the pause without starting anything (used when the VPN was started by the user). */
    fun clear(context: Context) {
        val app = context.applicationContext
        prefs(app).edit().remove(KEY_UNTIL).apply()
        cancelAlarm(app)
    }

    /**
     * End the pause and start the firewall. Returns false when Android does not allow it from here (VPN permission
     * revoked or background start refused); with [notifyOnFail] the user gets a notification instead.
     */
    fun resume(context: Context, notifyOnFail: Boolean = false): Boolean {
        val app = context.applicationContext
        clear(app)
        val started = runCatching {
            if (VpnService.prepare(app) != null) {
                false
            } else {
                val intent = Intent(app, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_START }
                ContextCompat.startForegroundService(app, intent)
                true
            }
        }.getOrDefault(false)
        if (!started && notifyOnFail) NotificationHelper.notifyPauseEnded(app)
        return started
    }

    /** Alarm fired. */
    fun onAlarm(context: Context) {
        resume(context, notifyOnFail = true)
    }

    /**
     * Called after a reboot / app update. Returns true when the boot logic must NOT restart the VPN because the
     * pause is still running (the alarm is scheduled again); if the pause already ended it resumes here.
     */
    fun handleBoot(context: Context): Boolean {
        val app = context.applicationContext
        val until = prefs(app).getLong(KEY_UNTIL, 0L)
        if (until <= 0L) return false
        return if (remaining(until, System.currentTimeMillis()) > 0L) {
            schedule(app, until)
            true
        } else {
            resume(app, notifyOnFail = true)
            true
        }
    }

    private fun pendingIntent(app: Context): PendingIntent {
        val intent = Intent(app, BootReceiver::class.java).apply { action = ACTION_PAUSE_END }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getBroadcast(app, REQUEST_CODE, intent, flags)
    }

    private fun schedule(app: Context, at: Long) {
        val alarm = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pending = pendingIntent(app)
        runCatching {
            if (Build.VERSION.SDK_INT >= 31 && !alarm.canScheduleExactAlarms()) error("exact alarms not allowed")
            if (Build.VERSION.SDK_INT >= 23) alarm.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
            else alarm.setExact(AlarmManager.RTC_WAKEUP, at, pending)
        }.onFailure {
            // Without the exact-alarm permission an inexact alarm may arrive a few minutes late, which is fine here.
            if (Build.VERSION.SDK_INT >= 23) alarm.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
            else alarm.set(AlarmManager.RTC_WAKEUP, at, pending)
        }
    }

    private fun cancelAlarm(app: Context) {
        (app.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(pendingIntent(app))
    }
}
