package com.hydra.firewall.vpn

import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import android.content.Context
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

object ConnectionHistory {
    data class Record(
        val id: Long,
        val timestamp: Long,
        val time: String,
        val uid: Int,
        val packageName: String?,
        val protocol: String,
        val network: NetworkKind,
        val destination: String,
        val source: String,
        val allowed: Boolean,
        val event: String,
        val repeatCount: Int = 1
    )

    private var maxRecords: Int = 500
    private val sequence = AtomicLong(0)
    private val buffer = ArrayDeque<Record>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private var retentionMillis: Long = 0L
    private var initialized = false
    private const val BLOCK_AGGREGATION_WINDOW_MS = 2_000L

    @Synchronized
    fun init(context: Context) {
        if (initialized) return
        initialized = true
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val uiPrefs = context.applicationContext.getSharedPreferences("firewall_settings", Context.MODE_PRIVATE)
        maxRecords = uiPrefs.getInt("history_max", prefs.getInt(KEY_MAX_RECORDS, 500)).coerceIn(100, 1000)
        val hours = prefs.getInt(KEY_RETENTION_HOURS, 12)
        retentionMillis = if (hours > 0) hours * 60L * 60L * 1000L else 0L
        pruneLocked(System.currentTimeMillis())
    }

    @Synchronized
    fun setRetentionHours(context: Context, hours: Int) {
        val safeHours = hours.coerceIn(0, 24 * 365)
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putInt(KEY_RETENTION_HOURS, safeHours).apply()
        retentionMillis = if (safeHours > 0) safeHours * 60L * 60L * 1000L else 0L
        pruneLocked(System.currentTimeMillis())
    }

    @Synchronized
    fun setMaxRecords(context: Context, value: Int) {
        maxRecords = value.coerceIn(100, 1000)
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putInt(KEY_MAX_RECORDS, maxRecords).apply()
        while (buffer.size > maxRecords) buffer.removeFirst()
    }

    @Synchronized
    fun maxRecords(context: Context): Int = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY_MAX_RECORDS, 500).coerceIn(100, 1000)

    @Synchronized
    fun retentionHours(context: Context): Int =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY_RETENTION_HOURS, 12)

    @Synchronized
    fun add(uid: Int, pkg: String?, protocol: String, network: NetworkKind, source: String, destination: String, allowed: Boolean, event: String) {
        val now = System.currentTimeMillis()

        // BLOCKED reconnect storms can generate hundreds of nearly identical records
        // in a few seconds. Keep a single representative record and aggregate the
        // number of attempts. We intentionally keep ALLOW/OPEN/FIRST-SEEN events
        // detailed because those are useful for forensic inspection.
        if (!allowed && event == "BLOCKED") {
            // Search recent history by destination instead of only looking at the
            // last record. A reconnect storm can alternate between many IPs, so
            // the same destination may reappear after several other blocked flows.
            val iterator = buffer.descendingIterator()
            while (iterator.hasNext()) {
                val existing = iterator.next()
                if (now - existing.timestamp > BLOCK_AGGREGATION_WINDOW_MS) break
                if (existing.allowed || existing.event != "BLOCKED") continue
                if (existing.uid != uid || existing.packageName != pkg ||
                    existing.protocol != protocol || existing.network != network ||
                    existing.destination != destination) continue

                buffer.remove(existing)
                buffer.addLast(
                    existing.copy(
                        timestamp = now,
                        time = fmt.format(Date(now)),
                        source = source,
                        repeatCount = existing.repeatCount + 1
                    )
                )
                pruneLocked(now)
                return
            }
        }

        buffer.addLast(Record(sequence.incrementAndGet(), now, fmt.format(Date(now)), uid, pkg, protocol, network, destination, source, allowed, event))
        pruneLocked(now)
        while (buffer.size > maxRecords) buffer.removeFirst()
    }

    private fun pruneLocked(now: Long) {
        if (retentionMillis <= 0L) return
        val cutoff = now - retentionMillis
        while (true) {
            val first = buffer.peekFirst() ?: break
            if (first.timestamp >= cutoff) break
            buffer.removeFirst()
        }
    }

    @Synchronized fun snapshot(): List<Record> = buffer.toList().asReversed()
    @Synchronized fun clear() = buffer.clear()

    private const val PREFS = "firewall_history"
    private const val KEY_RETENTION_HOURS = "retention_hours"
    private const val KEY_MAX_RECORDS = "max_records"
}
