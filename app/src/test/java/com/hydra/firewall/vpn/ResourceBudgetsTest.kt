package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ResourceBudgetsTest {

    @Test
    fun tcpSessionBudgetEnforcesLimitAndLeaseIsIdempotent() {
        val budget = BoundedSessionBudget(maxSessions = 3)
        val acquired = List(3) { budget.tryAcquire() }
        assertTrue(acquired.all { it != null })
        assertNull(budget.tryAcquire())
        acquired[0]!!.close()
        acquired[0]!!.close() // double close must not decrement twice
        assertEquals(2, budget.activeCount())
        val replacement = budget.tryAcquire()
        assertNotNull(replacement)
        replacement!!.close()
        acquired.drop(1).forEach { it!!.close() }
        assertEquals(0, budget.activeCount())
    }

    @Test
    fun tcpSessionBudgetDoesNotExceedLimitUnderConcurrency() {
        val max = 24
        val workers = 96
        val budget = BoundedSessionBudget(max)
        val ready = CountDownLatch(workers)
        val release = CountDownLatch(1)
        val leases = ConcurrentLinkedQueue<SessionBudgetLease>()
        val executor = Executors.newFixedThreadPool(workers)
        try {
            repeat(workers) {
                executor.submit {
                    budget.tryAcquire()?.let(leases::add)
                    ready.countDown()
                    release.await()
                }
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            assertEquals(max, leases.size)
            assertEquals(max, budget.activeCount())
            release.countDown()
            executor.shutdown()
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
            leases.forEach { it.close() }
            assertEquals(0, budget.activeCount())
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun udpBudgetEnforcesBothDatagramAndByteLimits() {
        val budget = BoundedUdpDatagramBudget(maxDatagrams = 3, maxBytes = 10)
        assertTrue(budget.tryReserve(7))
        assertTrue(budget.tryReserve(0)) // empty UDP datagrams still consume a queue slot
        assertFalse(budget.tryReserve(4)) // byte limit
        assertTrue(budget.tryReserve(3))
        assertFalse(budget.tryReserve(0)) // datagram-count limit
        assertEquals(BoundedUdpDatagramBudget.Snapshot(3, 10), budget.snapshot())

        budget.release(7)
        assertTrue(budget.tryReserve(6))
        assertEquals(BoundedUdpDatagramBudget.Snapshot(3, 9), budget.snapshot())
        budget.release(0)
        budget.release(3)
        budget.release(6)
        assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), budget.snapshot())
    }

    @Test
    fun udpBudgetNeverExceedsGlobalLimitsUnderConcurrency() {
        val maxDatagrams = 32
        val budget = BoundedUdpDatagramBudget(maxDatagrams, maxBytes = 320)
        val workers = 64
        val ready = CountDownLatch(workers)
        val release = CountDownLatch(1)
        val reservations = ConcurrentLinkedQueue<Int>()
        val executor = Executors.newFixedThreadPool(workers)
        try {
            repeat(workers) {
                executor.submit {
                    if (budget.tryReserve(10)) reservations.add(10)
                    ready.countDown()
                    release.await()
                }
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            assertEquals(maxDatagrams, reservations.size)
            assertEquals(BoundedUdpDatagramBudget.Snapshot(maxDatagrams, 320), budget.snapshot())
            release.countDown()
            executor.shutdown()
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
            reservations.forEach(budget::release)
            assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), budget.snapshot())
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }


    @Test
    fun productionTcpBudgetIsOneSharedCeilingForBothIpFamilies() {
        val leases = ArrayList<SessionBudgetLease>(TcpSessionBudget.MAX_ACTIVE_SESSIONS)
        try {
            repeat(TcpSessionBudget.MAX_ACTIVE_SESSIONS) {
                val lease = TcpSessionBudget.tryAcquire()
                assertNotNull("lease $it should fit in the shared budget", lease)
                leases += lease!!
            }
            assertEquals(TcpSessionBudget.MAX_ACTIVE_SESSIONS, TcpSessionBudget.activeCount())
            assertNull(TcpSessionBudget.tryAcquire())
        } finally {
            leases.forEach { it.close() }
        }
        assertEquals(0, TcpSessionBudget.activeCount())
    }

    @Test
    fun productionUdpBudgetIsSharedAndReleasesZeroLengthDatagrams() {
        val reservations = UdpPendingDatagramBudget.MAX_QUEUED_DATAGRAMS
        var reserved = 0
        try {
            repeat(reservations) {
                assertTrue(UdpPendingDatagramBudget.tryReserve(0))
                reserved++
            }
            assertFalse(UdpPendingDatagramBudget.tryReserve(0))
            assertEquals(reservations, UdpPendingDatagramBudget.snapshot().datagrams)
        } finally {
            repeat(reserved) { UdpPendingDatagramBudget.release(0) }
        }
        assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), UdpPendingDatagramBudget.snapshot())
        assertTrue(UdpPendingDatagramBudget.tryReserve(UdpPendingDatagramBudget.MAX_QUEUED_BYTES))
        assertFalse(UdpPendingDatagramBudget.tryReserve(1))
        assertEquals(
            UdpPendingDatagramBudget.MAX_QUEUED_BYTES,
            UdpPendingDatagramBudget.snapshot().bytes
        )
        assertTrue(UdpPendingDatagramBudget.release(UdpPendingDatagramBudget.MAX_QUEUED_BYTES))
        assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), UdpPendingDatagramBudget.snapshot())
    }

    @Test
    fun udpBudgetRejectsDoubleReleaseWithoutCorruptingCounters() {
        val budget = BoundedUdpDatagramBudget(maxDatagrams = 2, maxBytes = 16)
        assertTrue(budget.tryReserve(8))
        assertTrue(budget.release(8))
        assertFalse(budget.release(8))
        assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), budget.snapshot())
    }
}
