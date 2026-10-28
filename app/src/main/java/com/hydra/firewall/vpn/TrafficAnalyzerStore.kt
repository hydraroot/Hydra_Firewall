package com.hydra.firewall.vpn

import android.content.Context
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

/**
 * Lightweight, opt-in traffic analyzer for troubleshooting real network behavior.
 * It stores connection metadata only (no payload contents) and keeps data in memory.
 */
object TrafficAnalyzerStore {
    data class Event(
        val id: Long,
        val timestamp: Long,
        val time: String,
        val uid: Int,
        val packageName: String?,
        val protocol: String,
        val destination: String,
        val port: Int,
        val kind: String,
        val bytes: Int = 0,
        val domain: String? = null
    )

    private const val PREFS = "traffic_analyzer"
    private const val KEY_ENABLED = "enabled"
    private const val MAX_EVENTS = 2000
    private val sequence = AtomicLong(0)
    private val events = ArrayDeque<Event>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    @Volatile private var enabled = false

    @Synchronized
    fun init(context: Context) {
        enabled = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)
    }

    fun isEnabled(): Boolean = enabled

    @Synchronized
    fun setEnabled(context: Context, value: Boolean) {
        enabled = value
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, value).apply()
        if (!value) events.clear()
    }

    @Synchronized
    fun clear() = events.clear()

    @Synchronized
    fun snapshot(): List<Event> = events.toList().asReversed()

    fun recordConnection(uid: Int, packageName: String?, protocol: String, destination: String, port: Int, kind: String = "CONNECT") {
        if (!enabled) return
        add(Event(sequence.incrementAndGet(), System.currentTimeMillis(), "", uid, packageName, protocol, destination, port, kind))
    }

    fun recordData(uid: Int, packageName: String?, protocol: String, destination: String, port: Int, bytes: Int, kind: String) {
        if (!enabled) return
        add(Event(sequence.incrementAndGet(), System.currentTimeMillis(), "", uid, packageName, protocol, destination, port, kind, bytes.coerceAtLeast(0)))
    }

    fun recordDns(uid: Int, packageName: String?, domain: String, blocked: Boolean) {
        if (!enabled) return
        val clean = domain.trim().trimEnd('.').lowercase(Locale.US)
        if (clean.isEmpty()) return
        add(Event(sequence.incrementAndGet(), System.currentTimeMillis(), "", uid, packageName, "DNS", clean, 53, if (blocked) "DNS_BLOCK" else "DNS", domain = clean))
    }

    private fun add(raw: Event) {
        val event = raw.copy(time = fmt.format(Date(raw.timestamp)))
        synchronized(this) {
            events.addLast(event)
            while (events.size > MAX_EVENTS) events.removeFirst()
        }
    }

    fun youtubeEvents(): List<Event> = snapshot().filter { isYoutube(it.packageName, it.domain, it.destination) }

    fun isYoutube(packageName: String?, domain: String?, destination: String?): Boolean {
        val pkg = packageName?.lowercase(Locale.US).orEmpty()
        if (pkg == "com.google.android.youtube" || pkg.contains("youtube")) return true
        val text = (domain.orEmpty() + " " + destination.orEmpty()).lowercase(Locale.US)
        return text.contains("youtube") || text.contains("googlevideo") || text.contains("ytimg")
    }
}
