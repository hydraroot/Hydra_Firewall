package com.hydra.firewall.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import org.json.JSONObject

object VpnRecoveryScheduler {
    const val ACTION_RECOVER = "com.hydra.firewall.action.VPN_RECOVER"
    const val ACTION_HEALTH_CHECK = "com.hydra.firewall.action.VPN_HEALTH_CHECK"
    private const val REQUEST_RECOVER = 9452
    private const val REQUEST_HEALTH = 9453
    private const val PREFS = "hydra_vpn_recovery"
    private const val KEY_ATTEMPTS = "attempts"
    private const val KEY_WINDOW_START = "window_start"
    private const val MAX_ATTEMPTS = 6
    private const val WINDOW_MS = 10 * 60 * 1000L

    fun schedule(context: Context, delayMs: Long = 5_000L) {
        val app = context.applicationContext
        val now = System.currentTimeMillis()
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val windowStart = prefs.getLong(KEY_WINDOW_START, 0L)
        val attempts = if (windowStart == 0L || now - windowStart > WINDOW_MS) 0 else prefs.getInt(KEY_ATTEMPTS, 0)
        if (attempts >= MAX_ATTEMPTS) return
        val newAttempts = attempts + 1
        prefs.edit().putInt(KEY_ATTEMPTS, newAttempts).putLong(KEY_WINDOW_START, if (attempts == 0) now else windowStart).apply()
        scheduleAction(app, ACTION_RECOVER, REQUEST_RECOVER, delayMs)
    }

    fun scheduleHealthCheck(context: Context, delayMs: Long = 90_000L) {
        scheduleAction(context.applicationContext, ACTION_HEALTH_CHECK, REQUEST_HEALTH, delayMs)
    }

    fun markRecovered(context: Context) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt(KEY_ATTEMPTS, 0).putLong(KEY_WINDOW_START, 0L).apply()
        cancel(context)
        scheduleHealthCheck(context)
    }

    fun cancel(context: Context) {
        val app = context.applicationContext
        val alarm = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        cancelAction(app, alarm, ACTION_RECOVER, REQUEST_RECOVER)
        cancelAction(app, alarm, ACTION_HEALTH_CHECK, REQUEST_HEALTH)
    }

    private fun scheduleAction(app: Context, action: String, requestCode: Int, delayMs: Long) {
        val alarm = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(app, BootReceiver::class.java).apply { this.action = action }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        val pending = PendingIntent.getBroadcast(app, requestCode, intent, flags)
        val trigger = System.currentTimeMillis() + delayMs.coerceAtLeast(1000L)
        if (Build.VERSION.SDK_INT >= 23) alarm.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, pending)
        else alarm.setExact(AlarmManager.RTC_WAKEUP, trigger, pending)
    }

    private fun cancelAction(app: Context, alarm: AlarmManager, action: String, requestCode: Int) {
        val intent = Intent(app, BootReceiver::class.java).apply { this.action = action }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        alarm.cancel(PendingIntent.getBroadcast(app, requestCode, intent, flags))
    }
}
