package com.hydra.firewall.vpn

import android.content.Context
import android.content.Intent
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Small persistent undo stack for the most recent explicit access decisions. */
object DecisionHistory {
    private const val PREFS = "firewall_decision_history"
    private const val KEY = "entries"
    private const val MAX_ENTRIES = 20

    data class Entry(
        val id: String,
        val timestamp: Long,
        val uid: Int,
        val packageName: String?,
        val oldWifi: Boolean,
        val oldMobile: Boolean,
        val newWifi: Boolean,
        val newMobile: Boolean
    )

    @Synchronized
    fun record(
        context: Context,
        token: String,
        uid: Int,
        packageName: String?,
        oldWifi: Boolean,
        oldMobile: Boolean,
        newWifi: Boolean,
        newMobile: Boolean
    ) {
        val entries = read(context).toMutableList()
        entries.removeAll { it.id == token }
        entries.add(Entry(token, System.currentTimeMillis(), uid, packageName, oldWifi, oldMobile, newWifi, newMobile))
        while (entries.size > MAX_ENTRIES) entries.removeAt(0)
        write(context, entries)
    }

    @Synchronized
    fun undo(context: Context, token: String): Entry? {
        val entries = read(context).toMutableList()
        val entry = entries.findLast { it.id == token } ?: return null
        entries.removeAll { it.id == token }
        write(context, entries)
        RuleStore(context).apply {
            setWifiAllowed(entry.uid, entry.oldWifi)
            setMobileAllowed(entry.uid, entry.oldMobile)
        }

        // If the VPN is active, ask it to re-evaluate current sessions.
        // Starting an already-running service with ACTION_RULES_CHANGED is safe;
        // when it is stopped, the service records the diagnostic and does not
        // accidentally establish a VPN.
        runCatching {
            context.applicationContext.startService(
                Intent(context, FirewallVpnService::class.java).apply {
                    action = FirewallVpnService.ACTION_RULES_CHANGED
                }
            )
        }
        DiagnosticLogger.logServiceEvent(
            "ACCESS_DECISION_UNDO uid=${entry.uid} pkg=${entry.packageName ?: "unknown"} wifi=${entry.oldWifi} mobile=${entry.oldMobile}"
        )
        return entry
    }

    fun latest(context: Context): Entry? = read(context).lastOrNull()

    private fun read(context: Context): List<Entry> {
        val raw = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, "[]") ?: "[]"
        val json = runCatching { JSONArray(raw) }.getOrElse { JSONArray() }
        val result = ArrayList<Entry>(json.length())
        for (i in 0 until json.length()) {
            val o = json.optJSONObject(i) ?: continue
            result += Entry(
                id = o.optString("id", UUID.randomUUID().toString()),
                timestamp = o.optLong("timestamp", 0L),
                uid = o.optInt("uid", -1),
                packageName = if (o.isNull("packageName")) null else o.optString("packageName", ""),
                oldWifi = o.optBoolean("oldWifi", true),
                oldMobile = o.optBoolean("oldMobile", true),
                newWifi = o.optBoolean("newWifi", true),
                newMobile = o.optBoolean("newMobile", true)
            )
        }
        return result
    }

    private fun write(context: Context, entries: List<Entry>) {
        val json = JSONArray()
        entries.forEach { e ->
            json.put(JSONObject().apply {
                put("id", e.id)
                put("timestamp", e.timestamp)
                put("uid", e.uid)
                put("packageName", e.packageName ?: JSONObject.NULL)
                put("oldWifi", e.oldWifi)
                put("oldMobile", e.oldMobile)
                put("newWifi", e.newWifi)
                put("newMobile", e.newMobile)
            })
        }
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, json.toString()).apply()
    }
}
