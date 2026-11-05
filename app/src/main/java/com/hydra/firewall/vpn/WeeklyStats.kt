package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * Small per-day counters (allowed / blocked connections, ad and tracker blocks, blocked attempts per app) kept for
 * the last 7 days so Home can show a weekly summary. The history list only keeps ~12 hours, so this is separate.
 * Only counts and package names are stored; destinations are never stored here.
 */
object WeeklyStats {
    data class Day(
        val key: String,
        var allowed: Long = 0L,
        var blocked: Long = 0L,
        var ads: Long = 0L,
        val perApp: MutableMap<String, Long> = HashMap()
    )

    data class Summary(val allowed: Long, val blocked: Long, val ads: Long, val top: List<Pair<String, Long>>) {
        val isEmpty: Boolean get() = allowed + blocked + ads == 0L
    }

    private const val PREFS = "hydra_weekly_stats"
    private const val KEY_DAYS = "days"
    private const val WINDOW_DAYS = 7
    private const val FLUSH_EVERY_MS = 30_000L
    private const val KEY_REFRESH_MS = 60_000L

    // ---- pure logic (unit-tested) -----------------------------------------------------------------------------

    internal fun dayKey(ms: Long): String = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date(ms))

    internal fun windowKeys(now: Long, days: Int = WINDOW_DAYS): Set<String> {
        val cal = Calendar.getInstance().apply { timeInMillis = now }
        val out = LinkedHashSet<String>()
        repeat(days) {
            out.add(dayKey(cal.timeInMillis))
            cal.add(Calendar.DAY_OF_YEAR, -1)
        }
        return out
    }

    internal fun summarize(days: Collection<Day>, keys: Set<String>, topN: Int = 3): Summary {
        var allowed = 0L; var blocked = 0L; var ads = 0L
        val apps = HashMap<String, Long>()
        for (d in days) {
            if (d.key !in keys) continue
            allowed += d.allowed; blocked += d.blocked; ads += d.ads
            for ((pkg, n) in d.perApp) apps[pkg] = (apps[pkg] ?: 0L) + n
        }
        val top = apps.entries.sortedWith(compareByDescending<Map.Entry<String, Long>> { it.value }.thenBy { it.key })
            .take(topN).map { it.key to it.value }
        return Summary(allowed, blocked, ads, top)
    }

    internal fun encode(days: Collection<Day>): String {
        val arr = JSONArray()
        for (d in days) arr.put(JSONObject().apply {
            put("k", d.key); put("a", d.allowed); put("b", d.blocked); put("ads", d.ads)
            put("apps", JSONObject().apply { d.perApp.forEach { (p, n) -> put(p, n) } })
        })
        return arr.toString()
    }

    internal fun decode(json: String): List<Day> = runCatching {
        val arr = JSONArray(json)
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val key = o.optString("k").takeIf { it.length == 8 } ?: return@mapNotNull null
            val apps = HashMap<String, Long>()
            o.optJSONObject("apps")?.let { a -> a.keys().forEach { k -> apps[k] = a.optLong(k) } }
            Day(key, o.optLong("a"), o.optLong("b"), o.optLong("ads"), apps)
        }
    }.getOrDefault(emptyList())

    // ---- runtime ---------------------------------------------------------------------------------------------

    private val days = LinkedHashMap<String, Day>()
    private var appContext: Context? = null
    private var dirty = false
    private var lastFlush = 0L
    private var cachedKey = ""
    private var cachedKeyAt = 0L

    @Synchronized
    fun init(context: Context) {
        if (appContext != null) return
        val app = context.applicationContext
        appContext = app
        decode(app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_DAYS, "[]").orEmpty())
            .forEach { days[it.key] = it }
    }

    @Synchronized
    fun recordConnection(pkg: String?, allowed: Boolean, now: Long = System.currentTimeMillis()) {
        if (appContext == null) return
        val d = today(now)
        if (allowed) {
            d.allowed++
        } else {
            d.blocked++
            if (!pkg.isNullOrEmpty()) d.perApp[pkg] = (d.perApp[pkg] ?: 0L) + 1L
        }
        touch(now)
    }

    @Synchronized
    fun recordAdBlock(now: Long = System.currentTimeMillis()) {
        if (appContext == null) return
        today(now).ads++
        touch(now)
    }

    @Synchronized
    fun summary(now: Long = System.currentTimeMillis()): Summary {
        flush(now, force = true)
        return summarize(days.values, windowKeys(now))
    }

    private fun today(now: Long): Day {
        if (now - cachedKeyAt > KEY_REFRESH_MS || cachedKey.isEmpty()) {
            cachedKey = dayKey(now); cachedKeyAt = now
            val keep = windowKeys(now)
            if (days.keys.retainAll(keep)) dirty = true
        }
        return days.getOrPut(cachedKey) { Day(cachedKey) }
    }

    private fun touch(now: Long) {
        dirty = true
        flush(now, force = false)
    }

    private fun flush(now: Long, force: Boolean) {
        val app = appContext ?: return
        if (!dirty || (!force && now - lastFlush < FLUSH_EVERY_MS)) return
        runCatching {
            app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_DAYS, encode(days.values)).apply()
        }
        lastFlush = now
        dirty = false
    }
}
