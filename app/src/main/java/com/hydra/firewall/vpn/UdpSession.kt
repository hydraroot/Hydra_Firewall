package com.hydra.firewall.vpn

import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.DatagramChannel
import android.os.SystemClock

class UdpSession(
    val key: SessionKey,
    val uid: Int,
    val packageName: String?,
    val channel: DatagramChannel
) {
    var selectionKey: SelectionKey? = null
    var lastActivityMs: Long = System.currentTimeMillis()
    var closed: Boolean = false

    companion object {
        /** Re-check dynamic app/network policy at a bounded cadence, not for every UDP datagram. */
        const val POLICY_RECHECK_INTERVAL_MS = 1000L
        const val QUIC_RECHECK_INTERVAL_MS = 1000L
    }

    @Volatile private var lastPolicyCheckElapsedMs: Long = 0L
    @Volatile private var lastQuicCheckElapsedMs: Long = 0L
    @Volatile private var quicResultCache: QuicProtection.Result? = null

    fun needsPolicyRecheck(nowElapsedMs: Long = SystemClock.elapsedRealtime()): Boolean =
        lastPolicyCheckElapsedMs == 0L || nowElapsedMs - lastPolicyCheckElapsedMs >= POLICY_RECHECK_INTERVAL_MS

    fun markPolicyChecked(nowElapsedMs: Long = SystemClock.elapsedRealtime()) {
        lastPolicyCheckElapsedMs = nowElapsedMs
    }

    fun cachedQuicResult(nowElapsedMs: Long = SystemClock.elapsedRealtime()): QuicProtection.Result? {
        val cached = quicResultCache ?: return null
        return if (nowElapsedMs - lastQuicCheckElapsedMs < QUIC_RECHECK_INTERVAL_MS) cached else null
    }

    fun cacheQuicResult(result: QuicProtection.Result, nowElapsedMs: Long = SystemClock.elapsedRealtime()) {
        if (!result.cacheable) {
            invalidateQuicResult()
            return
        }
        quicResultCache = result
        lastQuicCheckElapsedMs = nowElapsedMs
    }

    fun invalidateQuicResult() {
        quicResultCache = null
        lastQuicCheckElapsedMs = 0L
    }

    /** Whole UDP datagrams waiting for a non-blocking channel write. */
    val toSocket = ArrayDeque<ByteBuffer>()
    var queuedBytes: Int = 0

    fun needsSocketWrite(): Boolean = toSocket.isNotEmpty()
}
