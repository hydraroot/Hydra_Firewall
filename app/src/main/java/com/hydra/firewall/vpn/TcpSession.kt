package com.hydra.firewall.vpn

import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel

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
        const val RECEIVE_BUFFER_LIMIT = 64 * 1024
        const val RETRANSMIT_MS = 1000L
        const val MAX_RETRANSMISSIONS = 6
    }

    var state: State = State.CONNECTING
    var clientExpectedSeq: Long = TcpSequence.add(clientInitialSeq, 1)
    var localNextSeq: Long = localInitialSeq
    var localAckedSeq: Long = localInitialSeq
    var clientWindow: Long = 65535L

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

    /** JA3/JA3N handshake fingerprinting state for the first bytes of this session. */
    val tlsFingerprintAccumulator = TlsFingerprintInspector.Accumulator()

    fun outstandingToClient(): Long = TcpSequence.distance(localAckedSeq, localNextSeq)

    fun availableClientWindow(): Long {
        return if (clientWindow > outstandingToClient()) clientWindow - outstandingToClient() else 0L
    }

    fun advertisedReceiveWindow(): Int {
        val available = RECEIVE_BUFFER_LIMIT - toSocketBytes
        return available.coerceIn(0, 65535)
    }

    fun needsSocketWrite(): Boolean = toSocket.isNotEmpty()

    fun needsSocketRead(): Boolean {
        if (state == State.CLOSED || remoteReadClosed) return false
        return availableClientWindow() > 0
    }
}
