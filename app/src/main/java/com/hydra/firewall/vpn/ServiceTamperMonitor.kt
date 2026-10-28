package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Distinguishes a VPN service stop the user (or Hydra itself, e.g. schedule)
 * asked for from one that wasn't: a crash, an OS/OEM battery-optimizer kill,
 * or another app/tool forcing the service down. START_STICKY already
 * restarts the service either way; this only adds visibility into *which*
 * kind of stop just happened, because a string of unexplained stops is a
 * meaningful signal (aggressive OEM task killer, malware trying to blind the
 * firewall, etc.) that silent auto-restart otherwise hides completely.
 *
 * Mechanism: any code path that intentionally stops the VPN calls
 * markIntentionalStop() immediately before doing so. onDestroy() checks the
 * flag; if it is missing, the stop is classified as unexpected and logged.
 * The flag is written to disk (not just memory) because an unexpected kill
 * can take the whole process down before onDestroy ever runs.
 */
object ServiceTamperMonitor {
    data class TamperEvent(val timestamp: Long, val time: String, val note: String)

    private const val PREFS = "service_tamper_monitor"
    private const val KEY_INTENTIONAL = "intentional_stop_pending"
    private const val KEY_EVENTS = "events_json"
    private const val MAX_EVENTS = 100
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private lateinit var prefs: android.content.SharedPreferences

    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    /** Call immediately before any intentional stop path (ACTION_STOP, onRevoke,
     *  schedule-driven stop, user toggle off). */
    fun markIntentionalStop() {
        if (!::prefs.isInitialized) return
        prefs.edit().putBoolean(KEY_INTENTIONAL, true).commit()
    }

    /** Call from onCreate/startVpn so a fresh, deliberate start doesn't get
     *  blamed later if the service is later killed unexpectedly mid-session. */
    fun clearIntentionalFlag() {
        if (!::prefs.isInitialized) return
        prefs.edit().putBoolean(KEY_INTENTIONAL, false).commit()
    }

    /** Call from onDestroy(). Returns true if this stop looks unexpected. */
    fun checkOnDestroy(): Boolean {
        if (!::prefs.isInitialized) return false
        val wasIntentional = prefs.getBoolean(KEY_INTENTIONAL, false)
        prefs.edit().putBoolean(KEY_INTENTIONAL, false).apply()
        if (!wasIntentional) {
            recordEvent("Servicio detenido sin solicitud explícita registrada")
        }
        return !wasIntentional
    }

    private fun recordEvent(note: String) {
        val events = eventsSnapshot().toMutableList()
        events.add(0, TamperEvent(System.currentTimeMillis(), fmt.format(Date()), note))
        while (events.size > MAX_EVENTS) events.removeAt(events.size - 1)
        val arr = JSONArray()
        events.forEach { e ->
            arr.put(JSONObject().apply {
                put("ts", e.timestamp); put("time", e.time); put("note", e.note)
            })
        }
        prefs.edit().putString(KEY_EVENTS, arr.toString()).apply()
    }

    fun eventsSnapshot(): List<TamperEvent> {
        if (!::prefs.isInitialized) return emptyList()
        val json = prefs.getString(KEY_EVENTS, null) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(json)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    add(TamperEvent(o.optLong("ts"), o.optString("time"), o.optString("note")))
                }
            }
        }.getOrDefault(emptyList())
    }

    fun clear() {
        if (::prefs.isInitialized) prefs.edit().remove(KEY_EVENTS).apply()
    }
}
