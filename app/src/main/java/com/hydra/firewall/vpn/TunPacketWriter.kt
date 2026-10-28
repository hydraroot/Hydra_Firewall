package com.hydra.firewall.vpn

import java.io.IOException
import java.io.OutputStream

/** Serializes writes from the TCP and UDP selector threads to the shared TUN. */
class TunPacketWriter(private val output: OutputStream) {
    @Synchronized
    @Throws(IOException::class)
    fun write(packet: ByteArray) {
        output.write(packet)
    }
}
