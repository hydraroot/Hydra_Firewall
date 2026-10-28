package com.hydra.firewall.vpn

/** Segment injected into the app/TUN side and waiting for a TCP ACK. */
class TcpPendingSegment(
    var sequence: Long,
    var payload: ByteArray,
    val fin: Boolean = false,
    val psh: Boolean = false,
    var lastSentMs: Long = 0L,
    var retransmissions: Int = 0
) {
    fun endSequence(): Long = TcpSequence.add(sequence, payload.size.toLong() + if (fin) 1L else 0L)
}
