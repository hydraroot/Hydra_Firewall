package com.hydra.firewall.vpn

import java.net.Inet6Address
import java.net.InetAddress

/**
 * Basic ICMPv6/NDP handling inside the application-facing TUN.
 *
 * This milestone handles ICMPv6 packets addressed to HYDRA's own IPv6
 * address and provides a small userspace NDP responder for the virtual
 * HYDRA address. It does not use privileged raw sockets on the physical
 * interface, so it intentionally does not proxy ICMPv6/NDP to wlan0.
 */
object Icmpv6Handler {
    private const val ICMPV6_HEADER = 8
    private const val TYPE_ECHO_REQUEST = 128
    private const val TYPE_ECHO_REPLY = 129
    private const val TYPE_ROUTER_SOLICITATION = 133
    private const val TYPE_ROUTER_ADVERTISEMENT = 134
    private const val TYPE_NEIGHBOR_SOLICITATION = 135
    private const val TYPE_NEIGHBOR_ADVERTISEMENT = 136

    private val vpnAddress: Inet6Address =
        InetAddress.getByName(FirewallVpnService.VPN_IPV6_ADDRESS) as Inet6Address

    fun handle(packet: ByteArray, ip: IPv6Header, tunWriter: TunPacketWriter): Boolean {
        val offset = ip.headerLength
        if (packet.size < offset + ICMPV6_HEADER) return true
        if (ip.nextHeader != IPv6Header.PROTOCOL_ICMPV6) return false

        val type = packet[offset].toInt() and 0xFF
        val code = packet[offset + 1].toInt() and 0xFF
        DiagnosticLogger.logIcmpv6(type, code, ip.sourceAddress, ip.destinationAddress)

        val localDestination = ip.destinationAddress.address.contentEquals(vpnAddress.address)

        return when (type) {
            TYPE_ECHO_REQUEST -> {
                if (localDestination) {
                    tunWriter.write(buildEchoReply(packet, ip))
                    true
                } else {
                    false
                }
            }
            TYPE_NEIGHBOR_SOLICITATION -> {
                if (isValidNeighborSolicitation(packet, ip) && packetContainsTarget(packet, ip, vpnAddress)) {
                    tunWriter.write(buildNeighborAdvertisement(packet, ip))
                    true
                } else {
                    // A NS for another node is still not forwarded to wlan0 in this milestone.
                    false
                }
            }
            TYPE_ROUTER_SOLICITATION -> {
                // Do not advertise HYDRA as an upstream router. RS/RA must be handled
                // by the real IPv6 link; this local VPN milestone only understands packets
                // addressed to the virtual endpoint.
                false
            }
            TYPE_NEIGHBOR_ADVERTISEMENT,
            TYPE_ROUTER_ADVERTISEMENT,
            TYPE_ECHO_REPLY -> true
            else -> true
        }
    }

    private fun buildEchoReply(packet: ByteArray, ip: IPv6Header): ByteArray {
        val icmpOffset = ip.headerLength
        val icmpLength = ip.totalLength - icmpOffset
        require(icmpLength >= ICMPV6_HEADER)

        val out = packet.copyOf(ip.totalLength)
        System.arraycopy(packet, 24, out, 8, 16)
        System.arraycopy(packet, 8, out, 24, 16)
        out[icmpOffset] = TYPE_ECHO_REPLY.toByte()
        out[icmpOffset + 1] = 0
        out[icmpOffset + 2] = 0
        out[icmpOffset + 3] = 0
        writeIcmpv6Checksum(out, icmpOffset, icmpLength)
        return out
    }

    private fun isValidNeighborSolicitation(packet: ByteArray, ip: IPv6Header): Boolean {
        val off = ip.headerLength
        val len = ip.totalLength - off
        // ICMPv6 NS fixed header: type/code/checksum + reserved(4) + target(16).
        return len >= 24
    }

    private fun packetContainsTarget(packet: ByteArray, ip: IPv6Header, target: Inet6Address): Boolean {
        val off = ip.headerLength + 8
        return packet.size >= off + 16 && packet.copyOfRange(off, off + 16).contentEquals(target.address)
    }

    private fun buildNeighborAdvertisement(packet: ByteArray, ip: IPv6Header): ByteArray {
        // Solicited/Override flags in NDP flags field: S=0x40000000, O=0x20000000.
        // Source and destination are swapped; target is HYDRA's virtual address.
        val out = ByteArray(IPv6Header.BASE_HEADER_LENGTH + 32)
        out[0] = 0x60
        putU16(out, 4, 32)
        out[6] = IPv6Header.PROTOCOL_ICMPV6.toByte()
        out[7] = 255.toByte()
        System.arraycopy(vpnAddress.address, 0, out, 8, 16)
        System.arraycopy(packet, 8, out, 24, 16)

        val icmp = 40
        out[icmp] = TYPE_NEIGHBOR_ADVERTISEMENT.toByte()
        out[icmp + 1] = 0
        // Flags + reserved: Solicited + Override.
        out[icmp + 4] = 0x60
        System.arraycopy(vpnAddress.address, 0, out, icmp + 8, 16)
        writeIcmpv6Checksum(out, icmp, 32)
        return out
    }

    private fun writeIcmpv6Checksum(packet: ByteArray, icmpOffset: Int, icmpLength: Int) {
        val src = InetAddress.getByAddress(packet.copyOfRange(8, 24)) as Inet6Address
        val dst = InetAddress.getByAddress(packet.copyOfRange(24, 40)) as Inet6Address
        val pseudo = ByteArray(40)
        System.arraycopy(src.address, 0, pseudo, 0, 16)
        System.arraycopy(dst.address, 0, pseudo, 16, 16)
        putU32(pseudo, 32, icmpLength.toLong())
        pseudo[39] = IPv6Header.PROTOCOL_ICMPV6.toByte()
        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, packet, icmpOffset, icmpLength)
        val checksum = (sum xor 0xFFFF) and 0xFFFF
        packet[icmpOffset + 2] = (checksum ushr 8).toByte()
        packet[icmpOffset + 3] = checksum.toByte()
    }

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private fun putU32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = (value ushr 24).toByte()
        data[offset + 1] = (value ushr 16).toByte()
        data[offset + 2] = (value ushr 8).toByte()
        data[offset + 3] = value.toByte()
    }
}
