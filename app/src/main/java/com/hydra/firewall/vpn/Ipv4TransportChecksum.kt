package com.hydra.firewall.vpn

/** RFC 768 checksum validation for UDP over IPv4. A zero UDP checksum is valid for IPv4. */
object Ipv4TransportChecksum {
    fun isValidUdp(packet: ByteArray, ip: IPv4Header, udp: UdpHeader): Boolean {
        val offset = ip.headerLength
        val length = udp.payloadLength + 8
        if (offset < 20 || length < 8 || offset + length > ip.totalLength || offset + length > packet.size) return false
        val checksum = u16(packet, offset + 6)
        if (checksum == 0) return true
        val pseudo = ByteArray(12)
        System.arraycopy(ip.sourceAddress.address, 0, pseudo, 0, 4)
        System.arraycopy(ip.destinationAddress.address, 0, pseudo, 4, 4)
        pseudo[8] = 0
        pseudo[9] = 17
        pseudo[10] = (length ushr 8).toByte()
        pseudo[11] = length.toByte()
        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, packet, offset, length)
        return sum == 0xFFFF
    }

    private fun u16(d: ByteArray, o: Int): Int =
        ((d[o].toInt() and 0xFF) shl 8) or (d[o + 1].toInt() and 0xFF)
}
