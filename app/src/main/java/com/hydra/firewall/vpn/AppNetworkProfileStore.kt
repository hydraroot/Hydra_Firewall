package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Builds a rolling "network fingerprint" per app (the set of destinations it
 * normally talks to) and flags destinations that show up for the first time
 * shortly after that app was updated. A legitimate app update sometimes adds
 * new endpoints too (new CDN, new feature) - this is a signal to review, not
 * an automatic block, which is why matches only ever produce an alert.
 *
 * This is the closest a non-root, on-device firewall can get to detecting a
 * malicious/compromised update (supply-chain style) from network behavior
 * alone: it cannot inspect the APK, but it can notice "this app has never
 * talked to this host in 40 days of history, and it just updated".
 */
object AppNetworkProfileStore {

    data class UpdateAnomaly(
        val id: Long,
        val timestamp: Long,
        val time: String,
        val packageName: String,
        val destination: String,
        val port: Int,
        val daysSinceUpdate: Double
    )

    private const val PREFS = "app_network_profile"
    private const val KEY_BASELINE_PREFIX = "baseline_" // + packageName -> JSON array of "host:port"
    private const val KEY_UPDATE_EPOCH_PREFIX = "updated_" // + packageName -> millis
    private const val KEY_REVIEW_WINDOW_DAYS = "review_window_days"
    private const val MAX_BASELINE_PER_APP = 300
    private const val MAX_ANOMALIES = 500
    private const val DEFAULT_REVIEW_WINDOW_DAYS = 7

    private lateinit var prefs: android.content.SharedPreferences
    private val sequence = AtomicLong(0)
    private val anomalies = ArrayDeque<UpdateAnomaly>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    // In-memory cache of baselines so the hot network path never touches disk.
    private val baselineCache = ConcurrentHashMap<String, MutableSet<String>>()
    private val updateEpochCache = ConcurrentHashMap<String, Long>()
    @Volatile private var enabled = true

    @Synchronized
    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        enabled = prefs.getBoolean("enabled", true)
        for (key in prefs.all.keys) {
            if (key.startsWith(KEY_UPDATE_EPOCH_PREFIX)) {
                val pkg = key.removePrefix(KEY_UPDATE_EPOCH_PREFIX)
                updateEpochCache[pkg] = prefs.getLong(key, 0L)
            }
        }
    }

    fun isEnabled(): Boolean = enabled
    fun setEnabled(context: Context, value: Boolean) {
        enabled = value
        prefs.edit().putBoolean("enabled", value).apply()
    }

    var reviewWindowDays: Int
        get() = if (::prefs.isInitialized) prefs.getInt(KEY_REVIEW_WINDOW_DAYS, DEFAULT_REVIEW_WINDOW_DAYS) else DEFAULT_REVIEW_WINDOW_DAYS
        set(value) { if (::prefs.isInitialized) prefs.edit().putInt(KEY_REVIEW_WINDOW_DAYS, value.coerceIn(1, 60)).apply() }

    /** Called from the network hot path. Cheap: in-memory set check + occasional persist. */
    fun recordDestination(uid: Int, packageName: String?, host: String, port: Int) {
        if (!enabled) return
        val pkg = packageName ?: return
        val key = "${host.lowercase(Locale.US)}:$port"

        val baseline = baselineCache.getOrPut(pkg) { loadBaseline(pkg) }
        val isNew = synchronized(baseline) {
            if (baseline.contains(key)) {
                false
            } else {
                baseline.add(key)
                if (baseline.size > MAX_BASELINE_PER_APP) {
                    // Drop an arbitrary older entry rather than growing unbounded;
                    // this only softens future novelty detection, it never crashes.
                    baseline.iterator().let { if (it.hasNext()) { it.next(); it.remove() } }
                }
                persistBaseline(pkg, baseline)
                true
            }
        }

        if (!isNew) return
        val updatedAt = updateEpochCache[pkg] ?: return
        val now = System.currentTimeMillis()
        val ageMs = now - updatedAt
        val windowMs = reviewWindowDays * 24L * 60 * 60 * 1000
        if (ageMs in 0..windowMs) {
            addAnomaly(pkg, host, port, ageMs / (24.0 * 60 * 60 * 1000))
        }
    }

    /** Called by the package-update watcher when Android reports a version change. */
    fun onAppUpdated(packageName: String) {
        if (!::prefs.isInitialized) return
        val now = System.currentTimeMillis()
        updateEpochCache[packageName] = now
        prefs.edit().putLong(KEY_UPDATE_EPOCH_PREFIX + packageName, now).apply()
        // Baseline is intentionally kept (not reset): the whole point is comparing
        // post-update traffic against everything seen before the update.
    }

    fun onAppRemoved(packageName: String) {
        if (!::prefs.isInitialized) return
        baselineCache.remove(packageName)
        updateEpochCache.remove(packageName)
        prefs.edit().remove(KEY_BASELINE_PREFIX + packageName).remove(KEY_UPDATE_EPOCH_PREFIX + packageName).apply()
    }

    @Synchronized
    fun anomalySnapshot(): List<UpdateAnomaly> = anomalies.toList().asReversed()

    @Synchronized
    fun dismissAnomaly(id: Long) {
        anomalies.removeAll { it.id == id }
    }

    @Synchronized
    fun clearAnomalies() = anomalies.clear()

    fun baselineSize(packageName: String): Int = baselineCache[packageName]?.size ?: loadBaseline(packageName).size

    private fun addAnomaly(pkg: String, host: String, port: Int, daysSinceUpdate: Double) {
        val event = UpdateAnomaly(
            id = sequence.incrementAndGet(),
            timestamp = System.currentTimeMillis(),
            time = fmt.format(Date()),
            packageName = pkg,
            destination = host,
            port = port,
            daysSinceUpdate = daysSinceUpdate
        )
        synchronized(this) {
            anomalies.addLast(event)
            while (anomalies.size > MAX_ANOMALIES) anomalies.removeFirst()
        }
    }

    private fun loadBaseline(pkg: String): MutableSet<String> {
        if (!::prefs.isInitialized) return java.util.concurrent.ConcurrentHashMap.newKeySet()
        val json = prefs.getString(KEY_BASELINE_PREFIX + pkg, null) ?: return java.util.concurrent.ConcurrentHashMap.newKeySet()
        val set = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        runCatching {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) set.add(arr.getString(i))
        }
        return set
    }

    private fun persistBaseline(pkg: String, baseline: Set<String>) {
        if (!::prefs.isInitialized) return
        // Persisting on every new entry is fine: new destinations per app are rare
        // compared to total packet volume, since this only runs on the JA3/first-hello path.
        val arr = JSONArray()
        baseline.forEach { arr.put(it) }
        prefs.edit().putString(KEY_BASELINE_PREFIX + pkg, arr.toString()).apply()
    }
}
