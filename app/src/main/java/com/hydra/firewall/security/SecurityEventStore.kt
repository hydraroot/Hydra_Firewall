package com.hydra.firewall.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

object SecurityEventStore {
    data class Event(val time: Long, val type: String, val title: String, val detail: String, val severity: Severity)
    private const val PREFS = "hydra_security_events"
    private const val KEY = "events"
    private const val KEY_BACKUP = "events_backup"
    private const val MAX = 300
    private const val MAX_DETAIL = 1500
    private const val SCHEMA = 3
    private val events = CopyOnWriteArrayList<Event>()
    @Volatile private var initialized = false

    @Synchronized fun init(context: Context) {
        if (initialized) return
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val main = prefs.getString(KEY, null)
        val backup = prefs.getString(KEY_BACKUP, null)
        val loaded = parse(main) ?: parse(backup)
        if (loaded != null) events.addAll(loaded.takeLast(MAX))
        initialized = true
    }

    private fun parse(raw: String?): List<Event>? = raw?.let {
        runCatching {
            val root = if (it.trimStart().startsWith("{")) JSONObject(it) else JSONObject().put("events", JSONArray(it))
            val a = root.optJSONArray("events") ?: JSONArray()
            buildList {
                for (i in 0 until a.length()) {
                    val o = a.getJSONObject(i)
                    val sev = runCatching { Severity.valueOf(o.getString("severity")) }.getOrElse { Severity.INFO }
                    add(Event(o.optLong("time"), o.optString("type"), o.optString("title"), o.optString("detail").take(MAX_DETAIL), sev))
                }
            }
        }.getOrNull()
    }

    @Synchronized fun record(context: Context, type: String, title: String, detail: String, severity: Severity) {
        init(context)
        events += Event(System.currentTimeMillis(), type, title, detail.take(MAX_DETAIL), severity)
        while (events.size > MAX) events.removeAt(0)
        persist(context)
    }

    fun snapshot(context: Context): List<Event> { init(context); return events.toList().reversed() }
    fun clear(context: Context) { init(context); events.clear(); persist(context) }

    @Synchronized private fun persist(context: Context) {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val old = prefs.getString(KEY, null)
        val a = JSONArray()
        events.forEach { e -> a.put(JSONObject().apply { put("time", e.time); put("type", e.type); put("title", e.title); put("detail", e.detail.take(MAX_DETAIL)); put("severity", e.severity.name) }) }
        val root = JSONObject().apply { put("schema", SCHEMA); put("events", a) }.toString()
        prefs.edit().apply {
            if (!old.isNullOrBlank()) putString(KEY_BACKUP, old)
            putString(KEY, root)
            apply()
        }
    }
}
