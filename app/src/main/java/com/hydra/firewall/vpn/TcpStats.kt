package com.hydra.firewall.vpn

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Aggregate TCP counters since the process started. They never hold hosts, IP addresses, ports or package
 * names, so they can be included in the diagnostic report safely.
 */
object TcpStats {
    enum class Counter(val label: String) {
        ESTABLISHED("established"),
        IDLE_TIMEOUT("idle_timeout"),
        RETRANSMIT_LIMIT("retransmit_limit"),
        REMOTE_READ_ERROR("remote_read_error"),
        REMOTE_WRITE_ERROR("remote_write_error"),
        RST_FROM_APP("rst_from_app"),
        CONNECT_FAILED("connect_failed"),
        CONNECT_TIMEOUT("connect_timeout"),
        WINDOW_UPDATES("window_updates")
    }

    private val counts = Array(Counter.values().size) { AtomicLong() }
    private val peakActive = AtomicInteger(0)
    private val startedAtMs = System.currentTimeMillis()

    fun inc(counter: Counter) {
        counts[counter.ordinal].incrementAndGet()
    }

    fun get(counter: Counter): Long = counts[counter.ordinal].get()

    /** Records the highest number of simultaneously active TCP sessions seen. */
    fun noteActive(activeSessions: Int) {
        while (true) {
            val current = peakActive.get()
            if (activeSessions <= current || peakActive.compareAndSet(current, activeSessions)) return
        }
    }

    fun peakActiveSessions(): Int = peakActive.get()

    internal fun resetForTest() {
        counts.forEach { it.set(0L) }
        peakActive.set(0)
    }

    /** Lines for the diagnostic report. */
    fun reportLines(): List<String> {
        val since = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(startedAtMs))
        val body = Counter.values().joinToString(" ") { "${it.label}=${get(it)}" }
        return listOf(
            "TCP counters since $since (reset when the app process restarts):",
            body,
            "peak_active_sessions=${peakActiveSessions()}"
        )
    }
}
