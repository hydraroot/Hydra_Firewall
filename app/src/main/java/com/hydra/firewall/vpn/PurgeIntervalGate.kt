package com.hydra.firewall.vpn

import java.util.concurrent.atomic.AtomicLong

/** Allows one caller to run a periodic cache purge for a shared resolver. */
internal class PurgeIntervalGate(private val intervalMs: Long) {
    private val lastRunElapsedMs = AtomicLong(Long.MIN_VALUE)

    init {
        require(intervalMs > 0L)
    }

    fun tryAcquire(nowElapsedMs: Long): Boolean {
        require(nowElapsedMs >= 0L)
        while (true) {
            val previous = lastRunElapsedMs.get()
            if (previous != Long.MIN_VALUE &&
                (nowElapsedMs < previous || nowElapsedMs - previous < intervalMs)
            ) return false
            if (lastRunElapsedMs.compareAndSet(previous, nowElapsedMs)) return true
        }
    }
}
