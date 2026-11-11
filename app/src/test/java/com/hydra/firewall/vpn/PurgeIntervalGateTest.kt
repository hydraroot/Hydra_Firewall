package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class PurgeIntervalGateTest {
    @Test
    fun allowsOnePurgePerInterval() {
        val gate = PurgeIntervalGate(5_000L)
        assertTrue(gate.tryAcquire(100L))
        assertFalse(gate.tryAcquire(4_999L))
        assertTrue(gate.tryAcquire(5_100L))
        assertFalse(gate.tryAcquire(5_100L))
        assertFalse(gate.tryAcquire(5_099L))
        assertTrue(gate.tryAcquire(10_100L))
    }

    @Test
    fun onlyOneConcurrentSelectorCanAcquirePurge() {
        val gate = PurgeIntervalGate(5_000L)
        val workers = 32
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val acquired = AtomicInteger(0)
        val threads = (0 until workers).map {
            thread(start = true) {
                ready.countDown()
                start.await()
                if (gate.tryAcquire(42_000L)) acquired.incrementAndGet()
            }
        }
        assertTrue(ready.await(5, java.util.concurrent.TimeUnit.SECONDS))
        start.countDown()
        threads.forEach { it.join() }
        assertEquals(1, acquired.get())
    }
}
