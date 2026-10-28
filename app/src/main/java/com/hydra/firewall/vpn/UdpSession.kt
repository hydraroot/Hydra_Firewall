package com.hydra.firewall.vpn

import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.DatagramChannel

class UdpSession(
    val key: SessionKey,
    val uid: Int,
    val packageName: String?,
    val channel: DatagramChannel
) {
    var selectionKey: SelectionKey? = null
    var lastActivityMs: Long = System.currentTimeMillis()
    var closed: Boolean = false

    /** Whole UDP datagrams waiting for a non-blocking channel write. */
    val toSocket = ArrayDeque<ByteBuffer>()
    var queuedBytes: Int = 0

    fun needsSocketWrite(): Boolean = toSocket.isNotEmpty()
}
