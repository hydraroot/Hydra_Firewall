package com.hydra.firewall.vpn

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

object TrafficStatsStore {
    data class Snapshot(
        val uid: Int,
        val packageName: String?,
        val connections: Long,
        val blocked: Long,
        val txBytes: Long,
        val rxBytes: Long,
        val blockedBytes: Long
    )

    private class MutableStat(val uid: Int, val packageName: String?) {
        val connections = AtomicLong(0)
        val blocked = AtomicLong(0)
        val txBytes = AtomicLong(0)
        val rxBytes = AtomicLong(0)
        val blockedBytes = AtomicLong(0)
    }

    private val stats = ConcurrentHashMap<Int, MutableStat>()

    private data class UsageKey(val uid: Int, val packageName: String?)
    private val dailyUsageBatches = ConcurrentHashMap<UsageKey, TrafficUsageBatcher>()
    private const val DAILY_USAGE_BATCH_BYTES = 64L * 1024L
    private const val MAX_DAILY_USAGE_BATCHES = 1024
    @Volatile private var dailyInitialized = false
    @Volatile private var lastDailyAllowed = 0L
    @Volatile private var lastDailyBlocked = 0L
    @Volatile private var lastDailyFlushMs = 0L

    fun init(context: Context) {
        DailyTrafficStore.init(context)
        AppDailyUsageStore.init(context)
        dailyInitialized = true
        val t = totals()
        lastDailyAllowed = t.allowedBytes
        lastDailyBlocked = t.blockedBytes
        lastDailyFlushMs = System.currentTimeMillis()
    }

    private fun stat(uid: Int, pkg: String?): MutableStat =
        stats.computeIfAbsent(uid) { MutableStat(uid, pkg) }

    fun recordConnection(uid: Int, pkg: String?) { stat(uid, pkg).connections.incrementAndGet() }
    fun recordBlocked(uid: Int, pkg: String?, bytes: Int = 0) {
        val s = stat(uid, pkg)
        s.blocked.incrementAndGet()
        if (bytes > 0) s.blockedBytes.addAndGet(bytes.toLong())
    }
    fun recordTx(uid: Int, pkg: String?, bytes: Int) {
        if (bytes > 0) {
            stat(uid, pkg).txBytes.addAndGet(bytes.toLong())
            accumulateDailyUsage(uid, pkg, bytes)
        }
    }
    fun recordRx(uid: Int, pkg: String?, bytes: Int) {
        if (bytes > 0) {
            stat(uid, pkg).rxBytes.addAndGet(bytes.toLong())
            accumulateDailyUsage(uid, pkg, bytes)
        }
    }

    /**
     * Keep the packet hot path lock-free for daily per-app usage. Small packet
     * updates are accumulated atomically and merged into the synchronized
     * persistent ledger in 64 KiB batches (or during an explicit flush).
     */
    private fun accumulateDailyUsage(uid: Int, pkg: String?, bytes: Int) {
        if (!dailyInitialized) return
        val key = UsageKey(uid, pkg)
        val batch = dailyUsageBatches[key] ?: run {
            if (dailyUsageBatches.size >= MAX_DAILY_USAGE_BATCHES) {
                // This should be rare (normal installed-app count is far lower).
                // Preserve accounting rather than dropping data if the safety cap is reached.
                AppDailyUsageStore.add(uid, pkg, bytes)
                return
            }
            dailyUsageBatches.computeIfAbsent(key) { TrafficUsageBatcher(DAILY_USAGE_BATCH_BYTES) }
        }
        val ready = batch.addAndDrainIfReady(bytes)
        if (ready > 0L) addDailyUsage(uid, pkg, ready)
    }

    /** Flushes sub-64 KiB tails for daily usage views and orderly service shutdown. */
    fun flushPendingDailyUsage() {
        if (!dailyInitialized) return
        for ((key, batch) in dailyUsageBatches) {
            val pending = batch.drain()
            if (pending > 0L) addDailyUsage(key.uid, key.packageName, pending)
        }
    }

    private fun addDailyUsage(uid: Int, pkg: String?, bytes: Long) {
        var remaining = bytes
        while (remaining > 0L) {
            val chunk = minOf(remaining, Int.MAX_VALUE.toLong()).toInt()
            AppDailyUsageStore.add(uid, pkg, chunk)
            remaining -= chunk.toLong()
        }
    }

    fun snapshot(uid: Int): Snapshot {
        val s = stats[uid]
        return Snapshot(
            uid,
            s?.packageName,
            s?.connections?.get() ?: 0L,
            s?.blocked?.get() ?: 0L,
            s?.txBytes?.get() ?: 0L,
            s?.rxBytes?.get() ?: 0L,
            s?.blockedBytes?.get() ?: 0L
        )
    }

    fun snapshotAll(): List<Snapshot> = stats.values.map { s ->
        Snapshot(s.uid, s.packageName, s.connections.get(), s.blocked.get(), s.txBytes.get(), s.rxBytes.get(), s.blockedBytes.get())
    }.sortedByDescending { it.connections + it.blocked }

    fun totals(): Totals {
        flushPendingDailyUsage()
        var allowed = 0L
        var blocked = 0L
        var blockedPackets = 0L
        for (s in stats.values) {
            allowed += s.txBytes.get() + s.rxBytes.get()
            blocked += s.blockedBytes.get()
            blockedPackets += s.blocked.get()
        }
        if (dailyInitialized) {
            val now = System.currentTimeMillis()
            if (now - lastDailyFlushMs >= 60_000L) {
                val allowedDelta = (allowed - lastDailyAllowed).coerceAtLeast(0L)
                val blockedDelta = (blocked - lastDailyBlocked).coerceAtLeast(0L)
                if (allowedDelta > 0L || blockedDelta > 0L) DailyTrafficStore.add(allowedDelta, blockedDelta)
                lastDailyAllowed = allowed
                lastDailyBlocked = blocked
                lastDailyFlushMs = now
            }
        }
        return Totals(allowedBytes = allowed, blockedBytes = blocked, blockedPackets = blockedPackets)
    }

    data class Totals(
        val allowedBytes: Long,
        val blockedBytes: Long,
        val blockedPackets: Long
    )

    fun clear() {
        flushPendingDailyUsage()
        stats.clear()
    }
}

/** Atomic byte bucket used to amortize per-packet daily-usage bookkeeping. */
internal class TrafficUsageBatcher(private val thresholdBytes: Long) {
    private val pending = AtomicLong(0L)

    init { require(thresholdBytes > 0L) }

    fun addAndDrainIfReady(bytes: Int): Long {
        if (bytes <= 0) return 0L
        val total = pending.addAndGet(bytes.toLong())
        return if (total >= thresholdBytes) drain() else 0L
    }

    fun drain(): Long = pending.getAndSet(0L).coerceAtLeast(0L)
    fun pendingBytes(): Long = pending.get()
}
