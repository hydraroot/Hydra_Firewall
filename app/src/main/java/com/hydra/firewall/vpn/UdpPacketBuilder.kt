package com.hydra.firewall.vpn

import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

/** Builds IPv4/UDP packets injected into the application-facing side of the TUN. */
object UdpPacketBuilder {
    private const val IP_HEADER = 20
    private const val UDP_HEADER = 8
    private const val PROTOCOL_UDP = 17
    private const val DEFAULT_TTL = 64
    private val ipIdentification = AtomicInteger((System.nanoTime() and 0xFFFF).toInt())

    fun build(
        source: InetAddress,
        destination: InetAddress,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray
    ): ByteArray {
        val src = source as? Inet4Address ?: throw IllegalArgumentException("IPv4 source required")
        val dst = destination as? Inet4Address ?: throw IllegalArgumentException("IPv4 destination required")
        require(sourcePort in 0..65535 && destinationPort in 0..65535)

        val totalLength = IP_HEADER + UDP_HEADER + payload.size
        require(totalLength <= 65535) { "UDP packet too large" }

        val packet = ByteArray(totalLength)
        packet[0] = 0x45
        packet[1] = 0
        putU16(packet, 2, totalLength)
        putU16(packet, 4, ipIdentification.getAndIncrement() and 0xFFFF)
        putU16(packet, 6, 0)
        packet[8] = DEFAULT_TTL.toByte()
        packet[9] = PROTOCOL_UDP.toByte()
        System.arraycopy(src.address, 0, packet, 12, 4)
        System.arraycopy(dst.address, 0, packet, 16, 4)
        putU16(packet, 10, InternetChecksum.checksum(packet, 0, IP_HEADER))

        val udp = IP_HEADER
        putU16(packet, udp, sourcePort)
        putU16(packet, udp + 2, destinationPort)
        putU16(packet, udp + 4, UDP_HEADER + payload.size)
        putU16(packet, udp + 6, 0)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, packet, udp + UDP_HEADER, payload.size)
        }

        val pseudo = ByteArray(12)
        System.arraycopy(src.address, 0, pseudo, 0, 4)
        System.arraycopy(dst.address, 0, pseudo, 4, 4)
        pseudo[8] = 0
        pseudo[9] = PROTOCOL_UDP.toByte()
        putU16(pseudo, 10, UDP_HEADER + payload.size)

        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, packet, udp, UDP_HEADER + payload.size)
        var checksum = (sum xor 0xFFFF) and 0xFFFF
        // For IPv4 UDP, a computed zero checksum is transmitted as all ones;
        // zero would mean "checksum disabled" on the wire.
        if (checksum == 0) checksum = 0xFFFF
        putU16(packet, udp + 6, checksum)
        return packet
    }

    private fun putU16(dst: ByteArray, offset: Int, value: Int) {
        dst[offset] = (value ushr 8).toByte()
        dst[offset + 1] = value.toByte()
    }
}
