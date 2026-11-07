package com.hydra.firewall.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

/**
 * "Allow this app for 1 hour": the app's rule is opened for a while and put back exactly as it was when the time is up
 * (including "no explicit rule"). The expiry is checked by an alarm, at boot and every time the app is opened.
 */
object TempAllowManager {
    const val ACTION_TEMP_ALLOW_END = "com.hydra.firewall.action.TEMP_ALLOW_END"
    private const val PREFS = "hydra_temp_allow"
    private const val KEY = "entries"
    private const val REQUEST_CODE = 9456

    data class Entry(val uid: Int, val until: Long, val hadRule: Boolean, val oldWifi: Boolean, val oldMobile: Boolean)

    // ---- pure logic (unit-tested) ---------------------------------------------------------------------------
    internal fun expired(entries: List<Entry>, now: Long): List<Entry> = entries.filter { it.until <= now }

    internal fun nextExpiry(entries: List<Entry>): Long? = entries.minOfOrNull { it.until }

    internal fun encode(entries: List<Entry>): String = JSONArray().also { arr ->
        entries.forEach { e ->
            arr.put(JSONObject().put("u", e.uid).put("t", e.until).put("h", e.hadRule).put("w", e.oldWifi).put("m", e.oldMobile))
        }
    }.toString()

    internal fun decode(raw: String): List<Entry> = runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            Entry(o.getInt("u"), o.getLong("t"), o.optBoolean("h"), o.optBoolean("w"), o.optBoolean("m"))
        }
    }.getOrDefault(emptyList())

    // ---- runtime ----------------------------------------------------------------------------------------------
    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun load(context: Context): List<Entry> = decode(prefs(context).getString(KEY, "[]").orEmpty())

    private fun save(context: Context, entries: List<Entry>) {
        prefs(context).edit().putString(KEY, encode(entries)).apply()
    }

    @Synchronized
    fun remainingMs(context: Context, uid: Int, now: Long = System.currentTimeMillis()): Long =
        load(context).firstOrNull { it.uid == uid }?.let { (it.until - now).coerceAtLeast(0L) } ?: 0L

    @Synchronized
    fun allow(context: Context, uid: Int, minutes: Int, now: Long = System.currentTimeMillis()) {
        val app = context.applicationContext
        val rules = RuleStore(app)
        val existing = load(app).firstOrNull { it.uid == uid }
        val before = rules.getRule(uid)
        // Keep the ORIGINAL state if the app was already under a temporary allowance.
        val entry = Entry(
            uid = uid,
            until = now + minutes.coerceIn(1, 24 * 60) * 60_000L,
            hadRule = existing?.hadRule ?: rules.hasExplicitRule(uid),
            oldWifi = existing?.oldWifi ?: before.wifiAllowed,
            oldMobile = existing?.oldMobile ?: before.mobileAllowed
        )
        rules.setWifiAllowed(uid, true)
        rules.setMobileAllowed(uid, true)
        val all = load(app).filter { it.uid != uid } + entry
        save(app, all)
        schedule(app, all)
        notifyService(app)
    }

    /** Put back every rule whose time is up. Returns true when something changed. */
    @Synchronized
    fun revertExpired(context: Context, now: Long = System.currentTimeMillis()): Boolean {
        val app = context.applicationContext
        val all = load(app)
        val done = expired(all, now)
        if (done.isEmpty()) {
            schedule(app, all)
            return false
        }
        val rules = RuleStore(app)
        done.forEach { e ->
            if (e.hadRule) {
                rules.setWifiAllowed(e.uid, e.oldWifi)
                rules.setMobileAllowed(e.uid, e.oldMobile)
            } else {
                rules.clearRule(e.uid)
            }
        }
        val left = all - done.toSet()
        save(app, left)
        schedule(app, left)
        notifyService(app)
        return true
    }

    private fun notifyService(app: Context) {
        if (!FirewallVpnService.isRunning) return
        runCatching {
            app.startService(Intent(app, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED })
        }
    }

    private fun pendingIntent(app: Context): PendingIntent {
        val intent = Intent(app, BootReceiver::class.java).apply { action = ACTION_TEMP_ALLOW_END }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getBroadcast(app, REQUEST_CODE, intent, flags)
    }

    private fun schedule(app: Context, entries: List<Entry>) {
        val alarm = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pending = pendingIntent(app)
        val at = nextExpiry(entries)
        if (at == null) {
            alarm.cancel(pending)
            return
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= 31 && !alarm.canScheduleExactAlarms()) error("exact alarms not allowed")
            if (Build.VERSION.SDK_INT >= 23) alarm.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
            else alarm.setExact(AlarmManager.RTC_WAKEUP, at, pending)
        }.onFailure {
            if (Build.VERSION.SDK_INT >= 23) alarm.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
            else alarm.set(AlarmManager.RTC_WAKEUP, at, pending)
        }
    }
}
