package com.hydra.firewall.vpn

import android.net.VpnService
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.Severity
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** A single TCP-session reservation. Closing it more than once is harmless. */
internal class SessionBudgetLease(private val releaseAction: () -> Unit) : AutoCloseable {
    private val released = AtomicBoolean(false)

    override fun close() {
        if (released.compareAndSet(false, true)) releaseAction()
    }
}

/** CAS-based bounded counter, independently testable without Android services. */
internal class BoundedSessionBudget(private val maxSessions: Int) {
    private val active = AtomicInteger(0)

    init {
        require(maxSessions > 0)
    }

    fun tryAcquire(): SessionBudgetLease? {
        while (true) {
            val current = active.get()
            if (current >= maxSessions) return null
            if (active.compareAndSet(current, current + 1)) {
                return SessionBudgetLease {
                    val remaining = active.decrementAndGet()
                    check(remaining >= 0) { "TCP session budget underflow" }
                }
            }
        }
    }

    fun activeCount(): Int = active.get()
}

/**
 * One cap shared by the IPv4 and IPv6 TCP adapters. A lease is acquired before
 * opening an upstream socket and transferred to TcpSession only on success.
 */
internal object TcpSessionBudget {
    const val MAX_ACTIVE_SESSIONS = 512
    private const val NOTIFY_EVERY_LIMIT_HITS = 50L
    private val budget = BoundedSessionBudget(MAX_ACTIVE_SESSIONS)
    private val limitHits = AtomicLong(0)

    fun tryAcquire(): SessionBudgetLease? = budget.tryAcquire()

    fun activeCount(): Int = budget.activeCount()

    fun recordLimitReached(service: VpnService, family: String) {
        val hits = limitHits.incrementAndGet()
        if (hits == 1L || hits % NOTIFY_EVERY_LIMIT_HITS == 0L) {
            runCatching {
                DiagnosticLogger.logServiceEvent(
                    "$family TCP SESSION LIMIT REACHED: $MAX_ACTIVE_SESSIONS (hit #$hits)"
                )
            }
        }
        if (hits % NOTIFY_EVERY_LIMIT_HITS == 0L) {
            runCatching {
                SecurityEventStore.record(
                    service,
                    "TCP_SESSION_LIMIT",
                    "Too many active connections",
                    "Hydra's shared IPv4/IPv6 TCP connection limit ($MAX_ACTIVE_SESSIONS) was reached " +
                        "$hits time(s); new TCP connections are being refused until existing ones close.",
                    Severity.INFO
                )
            }
        }
    }
}

/**
 * Thread-safe global budget for datagrams waiting to be written to upstream
 * UDP sockets. It is shared by both IP-family engines so their per-session
 * limits cannot add up to an unbounded process-wide queue.
 */
internal class BoundedUdpDatagramBudget(
    private val maxDatagrams: Int,
    private val maxBytes: Int
) {
    private var queuedDatagrams = 0
    private var queuedBytes = 0

    init {
        require(maxDatagrams > 0)
        require(maxBytes > 0)
    }

    @Synchronized
    fun tryReserve(datagramBytes: Int): Boolean {
        if (datagramBytes < 0 || queuedDatagrams >= maxDatagrams) return false
        if (datagramBytes > maxBytes - queuedBytes) return false
        queuedDatagrams++
        queuedBytes += datagramBytes
        return true
    }

    @Synchronized
    fun release(datagramBytes: Int): Boolean {
        if (datagramBytes < 0 || queuedDatagrams <= 0 || datagramBytes > queuedBytes) return false
        queuedDatagrams--
        queuedBytes -= datagramBytes
        return true
    }

    @Synchronized
    fun snapshot(): Snapshot = Snapshot(queuedDatagrams, queuedBytes)

    data class Snapshot(val datagrams: Int, val bytes: Int)
}

/** Shared across IPv4 and IPv6; 16 MiB / 4096 queued datagrams process-wide. */
internal object UdpPendingDatagramBudget {
    const val MAX_QUEUED_DATAGRAMS = 4096
    const val MAX_QUEUED_BYTES = 16 * 1024 * 1024
    private val budget = BoundedUdpDatagramBudget(MAX_QUEUED_DATAGRAMS, MAX_QUEUED_BYTES)
    private val droppedDatagrams = AtomicLong(0)

    fun tryReserve(datagramBytes: Int): Boolean = budget.tryReserve(datagramBytes)
    fun release(datagramBytes: Int): Boolean = budget.release(datagramBytes)
    fun snapshot(): BoundedUdpDatagramBudget.Snapshot = budget.snapshot()

    /** Shared drop counter lets both family engines rate-limit overload diagnostics. */
    fun recordQueueDrop(): Long = droppedDatagrams.incrementAndGet()
}
