package com.hydra.firewall.vpn

import java.net.Inet4Address
import java.util.concurrent.atomic.AtomicInteger

/** Builds IPv4/TCP packets injected into the app side of the TUN. */
object TcpPacketBuilder {
    private const val IP_HEADER = 20
    private const val TCP_HEADER = 20
    private const val FLAG_FIN = 0x01
    private const val FLAG_SYN = 0x02
    private const val FLAG_RST = 0x04
    private const val FLAG_PSH = 0x08
    private const val FLAG_ACK = 0x10

    private val ipIdentification = AtomicInteger((System.nanoTime() and 0xFFFF).toInt())

    fun build(
        session: TcpSession,
        seq: Long,
        ack: Long,
        syn: Boolean = false,
        ackFlag: Boolean = true,
        fin: Boolean = false,
        rst: Boolean = false,
        psh: Boolean = false,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val src = session.key.dstAddr as? Inet4Address
            ?: throw IllegalArgumentException("Solo soporta TCP/IPv4 en esta alpha")
        val dst = session.key.srcAddr as? Inet4Address
            ?: throw IllegalArgumentException("Solo soporta TCP/IPv4 en esta alpha")

        val options = if (syn) byteArrayOf(
            2, 4,
            ((session.localMss ushr 8) and 0xFF).toByte(), (session.localMss and 0xFF).toByte(),
            3, 3, 0,
            0
        ) else ByteArray(0)

        val tcpHeaderLength = TCP_HEADER + options.size
        val totalLength = IP_HEADER + tcpHeaderLength + payload.size
        require(totalLength <= 65535) { "TCP packet too large" }

        val packet = ByteArray(totalLength)
        packet[0] = 0x45
        packet[1] = 0
        putU16(packet, 2, totalLength)
        putU16(packet, 4, ipIdentification.getAndIncrement() and 0xFFFF)
        putU16(packet, 6, 0)
        packet[8] = 64
        packet[9] = 6
        System.arraycopy(src.address, 0, packet, 12, 4)
        System.arraycopy(dst.address, 0, packet, 16, 4)
        putU16(packet, 10, InternetChecksum.checksum(packet, 0, IP_HEADER))

        val tcp = IP_HEADER
        putU16(packet, tcp, session.key.dstPort)
        putU16(packet, tcp + 2, session.key.srcPort)
        putU32(packet, tcp + 4, seq)
        putU32(packet, tcp + 8, ack)
        packet[tcp + 12] = ((tcpHeaderLength / 4) shl 4).toByte()
        packet[tcp + 13] = (
            (if (fin) FLAG_FIN else 0) or
                (if (syn) FLAG_SYN else 0) or
                (if (rst) FLAG_RST else 0) or
                (if (psh) FLAG_PSH else 0) or
                (if (ackFlag) FLAG_ACK else 0)
            ).toByte()
        putU16(packet, tcp + 14, session.advertisedReceiveWindow())
        putU16(packet, tcp + 16, 0)
        putU16(packet, tcp + 18, 0)
        if (options.isNotEmpty()) System.arraycopy(options, 0, packet, tcp + TCP_HEADER, options.size)
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, packet, tcp + tcpHeaderLength, payload.size)

        val pseudo = ByteArray(12)
        System.arraycopy(src.address, 0, pseudo, 0, 4)
        System.arraycopy(dst.address, 0, pseudo, 4, 4)
        pseudo[8] = 0
        pseudo[9] = 6
        putU16(pseudo, 10, tcpHeaderLength + payload.size)

        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, packet, tcp, tcpHeaderLength + payload.size)
        putU16(packet, tcp + 16, (sum xor 0xFFFF) and 0xFFFF)
        return packet
    }

    private fun putU16(dst: ByteArray, offset: Int, value: Int) {
        dst[offset] = (value ushr 8).toByte()
        dst[offset + 1] = value.toByte()
    }

    private fun putU32(dst: ByteArray, offset: Int, value: Long) {
        dst[offset] = (value ushr 24).toByte()
        dst[offset + 1] = (value ushr 16).toByte()
        dst[offset + 2] = (value ushr 8).toByte()
        dst[offset + 3] = value.toByte()
    }
}
