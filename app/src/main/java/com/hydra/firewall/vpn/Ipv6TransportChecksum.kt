package com.hydra.firewall.vpn

import java.net.Inet6Address

/** RFC 8200 / RFC 2460 pseudo-header checksum validation for IPv6 upper-layer protocols. */
object Ipv6TransportChecksum {
    fun isValid(packet: ByteArray, ip: IPv6Header): Boolean {
        val offset = ip.headerLength
        val length = ip.totalLength - offset
        if (length <= 0 || offset < 40 || ip.totalLength > packet.size) return false
        val checksumOffset = when (ip.nextHeader) {
            IPv6Header.PROTOCOL_TCP -> offset + 16
            IPv6Header.PROTOCOL_UDP -> offset + 6
            IPv6Header.PROTOCOL_ICMPV6 -> offset + 2
            else -> return false
        }
        if (checksumOffset + 2 > ip.totalLength) return false
        if (ip.nextHeader == IPv6Header.PROTOCOL_UDP) {
            val csum = u16(packet, checksumOffset)
            if (csum == 0) return false // UDP checksum is mandatory for IPv6.
        }
        val src = ip.sourceAddress as? Inet6Address ?: return false
        val dst = ip.destinationAddress as? Inet6Address ?: return false
        val pseudo = ByteArray(40)
        System.arraycopy(src.address, 0, pseudo, 0, 16)
        System.arraycopy(dst.address, 0, pseudo, 16, 16)
        putU32(pseudo, 32, length.toLong())
        pseudo[39] = ip.nextHeader.toByte()

        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, packet, offset, length)
        // For a one's-complement checksum field, a valid packet sums to 0xFFFF.
        return sum == 0xFFFF
    }

    private fun u16(d: ByteArray, o: Int): Int =
        ((d[o].toInt() and 0xFF) shl 8) or (d[o + 1].toInt() and 0xFF)

    private fun putU32(d: ByteArray, o: Int, v: Long) {
        d[o] = (v ushr 24).toByte()
        d[o + 1] = (v ushr 16).toByte()
        d[o + 2] = (v ushr 8).toByte()
        d[o + 3] = v.toByte()
    }
}
