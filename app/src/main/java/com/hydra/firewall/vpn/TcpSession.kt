package com.hydra.firewall.vpn

import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import android.os.SystemClock

/** Per-connection TCP proxy state. Owned by the single selector thread. */
class TcpSession(
    val key: SessionKey,
    val uid: Int,
    val packageName: String?,
    val peerMss: Int,
    val peerWindowScale: Int,
    val localMss: Int,
    val channel: SocketChannel,
    val clientInitialSeq: Long,
    val localInitialSeq: Long
) {
    enum class State {
        CONNECTING,
        SYN_RECV,
        ESTABLISHED,
        CLOSING,
        CLOSED
    }

    companion object {
        /** Upload buffer per session (app -> real socket). 128 KB keeps worst case (512 sessions) near 64 MB. */
        const val RECEIVE_BUFFER_LIMIT = 128 * 1024
        const val RETRANSMIT_MS = 1000L
        const val MAX_RETRANSMISSIONS = 6
        /** Re-check dynamic policy once per second; explicit refresh events remain immediate. */
        const val POLICY_RECHECK_INTERVAL_MS = 1000L
    }

    var state: State = State.CONNECTING
    /** Shared IPv4/IPv6 session-cap reservation, released exactly once on close. */
    internal var budgetLease: SessionBudgetLease? = null
    var clientExpectedSeq: Long = TcpSequence.add(clientInitialSeq, 1)
    var localNextSeq: Long = localInitialSeq
    var localAckedSeq: Long = localInitialSeq
    var clientWindow: Long = 65535L

    /**
     * Window-scale shift that Hydra offered in its SYN-ACK AND the app also offered in its SYN
     * (RFC 7323: scaling only applies when both sides send the option). 0 = window field is unscaled.
     */
    var advertisedWindowShift: Int = 0
    private var lastAdvertisedBytes: Int = 0

    var synAckSent = false
    var synAckRetries = 0
    var lastSynAckMs = 0L
    var clientFinSeen = false
    var pendingFinSequence: Long? = null
    var pendingFinPayloadLength: Int = 0
    var serverFinSent = false
    var serverFinSequence: Long = 0L
    var remoteEof = false
    var remoteReadClosed = false
    var outputShutdown = false
    var createdMs: Long = System.currentTimeMillis()
    var lastActivityMs: Long = createdMs
    var selectionKey: SelectionKey? = null

    @Volatile private var lastPolicyCheckElapsedMs: Long = 0L

    fun needsPolicyRecheck(nowElapsedMs: Long = SystemClock.elapsedRealtime()): Boolean =
        lastPolicyCheckElapsedMs == 0L || nowElapsedMs - lastPolicyCheckElapsedMs >= POLICY_RECHECK_INTERVAL_MS

    fun markPolicyChecked(nowElapsedMs: Long = SystemClock.elapsedRealtime()) {
        lastPolicyCheckElapsedMs = nowElapsedMs
    }

    /** Bytes received from the app and waiting to be written to the real socket. */
    val toSocket = java.util.ArrayDeque<ByteBuffer>()
    var toSocketBytes: Int = 0

    /** Data/FIN injected toward the app and waiting for TCP ACKs. */
    val toClient = java.util.ArrayDeque<TcpPendingSegment>()

    /** Bounded receive-side TCP reassembly for out-of-order app/TUN payloads. */
    val reassembly = TcpReassembly(
        maxSegments = 64,
        maxBytes = RECEIVE_BUFFER_LIMIT,
        maxAhead = RECEIVE_BUFFER_LIMIT
    )

    /** Estado de lectura del ClientHello (SNI) para los primeros bytes de esta sesión. */
    val tlsSniAccumulator = TlsSniInspector.Accumulator()

    fun outstandingToClient(): Long = TcpSequence.distance(localAckedSeq, localNextSeq)

    fun availableClientWindow(): Long {
        return if (clientWindow > outstandingToClient()) clientWindow - outstandingToClient() else 0L
    }

    /** Free space for new app data; same accounting used to accept/drop payload in the engines. */
    private fun freeReceiveSpace(): Int =
        (RECEIVE_BUFFER_LIMIT - toSocketBytes - reassembly.bufferedBytes()).coerceAtLeast(0)

    /**
     * Value for the 16-bit TCP window field. The window in SYN/SYN-ACK is never scaled; afterwards it is
     * divided by 2^advertisedWindowShift (rounding down, so Hydra never promises more than it can buffer).
     * Remembers what was advertised so [needsWindowUpdate] can tell when the app should be re-informed.
     */
    fun advertisedReceiveWindow(syn: Boolean = false): Int {
        val shift = if (syn) 0 else advertisedWindowShift
        val raw = (freeReceiveSpace() ushr shift).coerceIn(0, 65535)
        lastAdvertisedBytes = raw shl shift
        return raw
    }

    /** True when the buffer drained enough that an ACK carrying a larger window is worth sending. */
    fun needsWindowUpdate(): Boolean {
        val current = (freeReceiveSpace() ushr advertisedWindowShift).coerceIn(0, 65535) shl advertisedWindowShift
        val threshold = minOf(RECEIVE_BUFFER_LIMIT / 2, 2 * localMss)
        return current - lastAdvertisedBytes >= threshold
    }

    fun needsSocketWrite(): Boolean = toSocket.isNotEmpty()

    fun needsSocketRead(): Boolean {
        if (state == State.CLOSED || remoteReadClosed) return false
        return availableClientWindow() > 0
    }
}
