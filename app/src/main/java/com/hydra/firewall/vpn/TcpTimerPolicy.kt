package com.hydra.firewall.vpn

/**
 * Pure timer rules shared by the IPv4 and IPv6 TCP engines (kept separate so they can be unit-tested).
 */
internal object TcpTimerPolicy {
    /** Backoff doubles up to 2^5 (1, 2, 4, 8, 16, 32 s); MAX_RETRANSMISSIONS still bounds the attempts. */
    private const val MAX_BACKOFF_STEPS = 5

    /** Established, fully open connections (push, chat, long polls) may stay silent for a long time. */
    const val IDLE_ESTABLISHED_MS = 30 * 60_000L

    /** Connecting, closing and half-closed sessions keep the short timeout. */
    const val IDLE_DEFAULT_MS = 5 * 60_000L

    /** About 80% of TcpSessionBudget.MAX_ACTIVE_SESSIONS: above this, idle sessions must free slots quickly. */
    const val BUSY_SESSION_THRESHOLD = 410

    fun retransmitDelayMs(retransmissions: Int): Long =
        TcpSession.RETRANSMIT_MS shl retransmissions.coerceIn(0, MAX_BACKOFF_STEPS)

    fun idleTimeoutMs(state: TcpSession.State, halfClosed: Boolean, activeSessions: Int): Long =
        if (state == TcpSession.State.ESTABLISHED && !halfClosed && activeSessions < BUSY_SESSION_THRESHOLD) {
            IDLE_ESTABLISHED_MS
        } else {
            IDLE_DEFAULT_MS
        }
}
