package com.hydra.firewall.vpn

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

/** Keeps a tiny 8-day rolling traffic summary. Writes to disk at most once per minute. */
object DailyTrafficStore {
    data class Day(val key: String, val allowed: Long, val blocked: Long)
    private const val PREFS = "hydra_daily_traffic"
    private const val FLUSH_MS = 60_000L
    private var initialized = false
    private var context: Context? = null
    private var dayKey = ""
    private var allowed = 0L
    private var blocked = 0L
    private var lastFlush = 0L

    private fun key(now: Long = System.currentTimeMillis()): String = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(now)

    @Synchronized fun init(ctx: Context) {
        if (initialized) return
        context = ctx.applicationContext
        val p = context!!.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        dayKey = key()
        allowed = p.getLong("${dayKey}_allowed", 0L)
        blocked = p.getLong("${dayKey}_blocked", 0L)
        initialized = true
        lastFlush = System.currentTimeMillis()
        pruneOld(p)
    }

    @Synchronized fun add(allowedBytes: Long, blockedBytes: Long) {
        if (!initialized) return
        val today = key()
        if (today != dayKey) {
            flushLocked()
            dayKey = today
            allowed = 0L
            blocked = 0L
        }
        allowed += allowedBytes.coerceAtLeast(0L)
        blocked += blockedBytes.coerceAtLeast(0L)
        if (System.currentTimeMillis() - lastFlush >= FLUSH_MS) flushLocked()
    }

    @Synchronized fun flush() { if (initialized) flushLocked() }

    @Synchronized fun today(): Day = Day(dayKey, allowed, blocked)

    @Synchronized fun lastDays(count: Int = 7): List<Day> {
        if (System.currentTimeMillis() - lastFlush >= FLUSH_MS) flushLocked()
        val p = context?.getSharedPreferences(PREFS, Context.MODE_PRIVATE) ?: return listOf(today())
        val cal = Calendar.getInstance()
        val out = ArrayList<Day>(count)
        repeat(count) {
            val k = key(cal.timeInMillis)
            out += Day(k, if (k == dayKey) allowed else p.getLong("${k}_allowed", 0L), if (k == dayKey) blocked else p.getLong("${k}_blocked", 0L))
            cal.add(Calendar.DAY_OF_YEAR, -1)
        }
        return out
    }

    private fun flushLocked() {
        val p = context?.getSharedPreferences(PREFS, Context.MODE_PRIVATE) ?: return
        p.edit().putLong("${dayKey}_allowed", allowed).putLong("${dayKey}_blocked", blocked).apply()
        lastFlush = System.currentTimeMillis()
        pruneOld(p)
    }

    private fun pruneOld(p: android.content.SharedPreferences) {
        val cutoff = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -8) }
        val cutoffKey = key(cutoff.timeInMillis)
        val e = p.edit()
        p.all.keys.filter { it.matches(Regex("\\d{4}-\\d{2}-\\d{2}_(allowed|blocked)")) && it.substringBefore('_') < cutoffKey }
            .forEach(e::remove)
        e.apply()
    }
}
