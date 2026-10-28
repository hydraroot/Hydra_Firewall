package com.hydra.firewall.vpn

import android.content.Context
import android.os.PowerManager
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

/**
 * Cross-references live traffic with Doze state. Android already suspends
 * most background network access during Doze/App Standby for non-exempt
 * apps, so traffic that still gets through from an app that is not an
 * obvious exception (foreground, whitelisted, high-priority FCM, etc.) is
 * worth a look: at best it's a legitimate background-exempt app the person
 * forgot about, at worst it's something deliberately fighting battery
 * restrictions to stay connected.
 *
 * This does not (and, without root, cannot) determine *why* Android let the
 * traffic through - it only correlates "device is idle" with "this app just
 * sent/received data", which is the strongest signal available at the
 * VpnService layer.
 */
class DozeAnomalyMonitor(context: Context) {
    data class Anomaly(
        val id: Long,
        val timestamp: Long,
        val time: String,
        val uid: Int,
        val packageName: String?,
        val bytes: Int
    )

    private val appContext = context.applicationContext
    private val powerManager = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val sequence = AtomicLong(0)
    private var lastCheckedEventId = 0L

    fun isDeviceIdle(): Boolean = if (android.os.Build.VERSION.SDK_INT >= 23) powerManager.isDeviceIdleMode else false

    /**
     * Call periodically (e.g. every 30-60s alongside the existing policy
     * refresh loop). Looks only at TrafficAnalyzerStore events newer than the
     * last check, so this stays cheap regardless of how often it's called.
     */
    fun poll() {
        if (!enabled) return
        if (!isDeviceIdle()) return
        if (!TrafficAnalyzerStore.isEnabled()) return // needs the analyzer's event stream to correlate against

        val recent = TrafficAnalyzerStore.snapshot()
        var newestSeen = lastCheckedEventId
        for (event in recent) {
            if (event.id <= lastCheckedEventId) break
            newestSeen = maxOf(newestSeen, event.id)
            if (event.kind == "C2S_DATA" || event.kind == "S2C_DATA") {
                addAnomaly(event.uid, event.packageName, event.bytes)
            }
        }
        lastCheckedEventId = newestSeen
    }

    @Volatile var enabled = true

    @Synchronized
    private fun addAnomaly(uid: Int, packageName: String?, bytes: Int) {
        val event = Anomaly(sequence.incrementAndGet(), System.currentTimeMillis(), fmt.format(Date()), uid, packageName, bytes)
        anomalies.addLast(event)
        while (anomalies.size > MAX_ANOMALIES) anomalies.removeFirst()
    }

    companion object {
        private const val MAX_ANOMALIES = 300
        private val anomalies = ArrayDeque<Anomaly>()

        @Synchronized
        fun snapshot(): List<Anomaly> = anomalies.toList().asReversed()

        @Synchronized
        fun clear() = anomalies.clear()

        /** Per-app rollup so the UI doesn't have to show hundreds of individual data events. */
        @Synchronized
        fun byApp(): List<Pair<String, Int>> = anomalies
            .groupBy { it.packageName ?: "uid:${it.uid}" }
            .map { (pkg, list) -> pkg to list.size }
            .sortedByDescending { it.second }
    }
}
