package com.hydra.firewall.vpn

import java.net.InetAddress

/**
 * Minimal IPv4 ICMP support for the application-facing TUN.
 *
 * HYDRA cannot proxy arbitrary ICMP echo traffic to the physical interface
 * without privileged raw-socket access. We therefore provide a correct local
 * echo responder for the virtual VPN address and explicit diagnostics for
 * external ICMP requests instead of silently dropping them.
 */
object Icmpv4Handler {
    private const val TYPE_ECHO_REQUEST = 8
    private const val TYPE_ECHO_REPLY = 0
    private const val MIN_ICMP_HEADER = 8
    private val vpnAddress: InetAddress = InetAddress.getByName(FirewallVpnService.VPN_ADDRESS)

    fun handle(packet: ByteArray, ip: IPv4Header, tunWriter: TunPacketWriter): Boolean {
        val offset = ip.headerLength
        val icmpLength = ip.totalLength - offset
        if (icmpLength < MIN_ICMP_HEADER || packet.size < offset + MIN_ICMP_HEADER) return true
        if (ip.protocol != IPv4Header.PROTOCOL_ICMP) return false

        val type = packet[offset].toInt() and 0xFF
        val code = packet[offset + 1].toInt() and 0xFF
        DiagnosticLogger.logServiceEvent(
            "ICMPV4 type=$type code=$code src=${ip.sourceAddress.hostAddress} dst=${ip.destinationAddress.hostAddress}"
        )

        if (type != TYPE_ECHO_REQUEST || code != 0) return true
        if (!ip.destinationAddress.address.contentEquals(vpnAddress.address)) return false

        val out = packet.copyOf(ip.totalLength)
        val src = ip.sourceAddress.address.copyOf()
        val dst = ip.destinationAddress.address.copyOf()
        System.arraycopy(dst, 0, out, 12, 4)
        System.arraycopy(src, 0, out, 16, 4)

        out[offset] = TYPE_ECHO_REPLY.toByte()
        out[offset + 1] = 0
        out[offset + 2] = 0
        out[offset + 3] = 0
        val checksum = InternetChecksum.compute(out, offset, icmpLength) xor 0xFFFF
        out[offset + 2] = (checksum ushr 8).toByte()
        out[offset + 3] = checksum.toByte()

        // Recalculate IPv4 header checksum because source/destination changed.
        out[10] = 0
        out[11] = 0
        val ipChecksum = InternetChecksum.compute(out, 0, ip.headerLength) xor 0xFFFF
        out[10] = (ipChecksum ushr 8).toByte()
        out[11] = ipChecksum.toByte()

        tunWriter.write(out)
        DiagnosticLogger.logServiceEvent("ICMPV4 LOCAL_ECHO_REPLY dst=${ip.sourceAddress.hostAddress}")
        return true
    }
}
