package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpTimerPolicyTest {
    @Test
    fun retransmitBackoffDoublesFrom1sUpTo32s() {
        val delays = (0..8).map { TcpTimerPolicy.retransmitDelayMs(it) }
        assertEquals(listOf(1000L, 2000L, 4000L, 8000L, 16000L, 32000L, 32000L, 32000L, 32000L), delays)
    }

    @Test
    fun retransmitDelayIgnoresNegativeCounts() {
        assertEquals(1000L, TcpTimerPolicy.retransmitDelayMs(-3))
    }

    @Test
    fun establishedOpenSessionsGetLongIdleTimeoutWhenNotBusy() {
        assertEquals(
            TcpTimerPolicy.IDLE_ESTABLISHED_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.ESTABLISHED, halfClosed = false, activeSessions = 10)
        )
    }

    @Test
    fun busyEngineFallsBackToShortIdleTimeout() {
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(
                TcpSession.State.ESTABLISHED, halfClosed = false,
                activeSessions = TcpTimerPolicy.BUSY_SESSION_THRESHOLD
            )
        )
    }

    @Test
    fun nonEstablishedOrHalfClosedSessionsKeepShortIdleTimeout() {
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.CONNECTING, halfClosed = false, activeSessions = 1)
        )
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.SYN_RECV, halfClosed = false, activeSessions = 1)
        )
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.ESTABLISHED, halfClosed = true, activeSessions = 1)
        )
    }

    @Test
    fun longIdleTimeoutAppliesJustBelowTheBusyThreshold() {
        assertEquals(
            TcpTimerPolicy.IDLE_ESTABLISHED_MS,
            TcpTimerPolicy.idleTimeoutMs(
                TcpSession.State.ESTABLISHED, halfClosed = false,
                activeSessions = TcpTimerPolicy.BUSY_SESSION_THRESHOLD - 1
            )
        )
    }

    @Test
    fun closingAndClosedSessionsKeepShortIdleTimeout() {
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.CLOSING, halfClosed = false, activeSessions = 1)
        )
        assertEquals(
            TcpTimerPolicy.IDLE_DEFAULT_MS,
            TcpTimerPolicy.idleTimeoutMs(TcpSession.State.CLOSED, halfClosed = false, activeSessions = 1)
        )
    }

    @Test
    fun busyThresholdStaysBelowSessionCap() {
        assertTrue(TcpTimerPolicy.BUSY_SESSION_THRESHOLD < TcpSessionBudget.MAX_ACTIVE_SESSIONS)
    }
}
