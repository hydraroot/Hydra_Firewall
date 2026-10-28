package com.hydra.firewall.vpn

import java.net.InetAddress

/**
 * IPv6 header parser with bounded support for common extension headers.
 * Fragmented packets remain unsupported in this milestone.
 */
data class IPv6Header(
    val payloadLength: Int,
    val totalLength: Int,
    val nextHeader: Int,
    val hopLimit: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val headerLength: Int
) {
    companion object {
        const val BASE_HEADER_LENGTH = 40
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17
        const val PROTOCOL_ICMPV6 = 58
        const val NEXT_HOP_BY_HOP = 0
        const val NEXT_ROUTING = 43
        const val NEXT_FRAGMENT = 44
        const val NEXT_ESP = 50
        const val NEXT_AH = 51
        const val NEXT_DESTINATION = 60

        private const val MAX_EXTENSION_HEADERS = 8
        private const val MAX_EXTENSION_BYTES = 256

        fun hasFragmentHeader(packet: ByteArray): Boolean {
            if (packet.size < BASE_HEADER_LENGTH) return false
            if (((packet[0].toInt() and 0xFF) ushr 4) != 6) return false
            val payloadLength = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
            val total = BASE_HEADER_LENGTH + payloadLength
            if (total < BASE_HEADER_LENGTH || total > packet.size) return false
            var next = packet[6].toInt() and 0xFF
            var offset = BASE_HEADER_LENGTH
            var count = 0
            while (next == NEXT_HOP_BY_HOP || next == NEXT_ROUTING || next == NEXT_DESTINATION || next == NEXT_AH) {
                if (++count > 8 || offset + 2 > total) return false
                val len = if (next == NEXT_AH) {
                    ((packet[offset + 1].toInt() and 0xFF) + 2) * 4
                } else {
                    (((packet[offset + 1].toInt() and 0xFF) + 1) * 8)
                }
                if (len < 8 || offset + len > total) return false
                next = packet[offset].toInt() and 0xFF
                offset += len
            }
            return next == NEXT_FRAGMENT && offset + 8 <= total
        }

        fun parse(packet: ByteArray): IPv6Header? {
            if (packet.size < BASE_HEADER_LENGTH) return null
            if (((packet[0].toInt() and 0xFF) ushr 4) != 6) return null

            val payloadLength = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
            // This engine does not implement RFC 2675 jumbograms; payload length 0
            // is therefore treated as malformed rather than guessed.
            if (payloadLength == 0) return null
            val total = BASE_HEADER_LENGTH + payloadLength
            if (total < BASE_HEADER_LENGTH || total > packet.size) return null

            var next = packet[6].toInt() and 0xFF
            var offset = BASE_HEADER_LENGTH
            var extBytes = 0
            var extCount = 0

            while (next == NEXT_HOP_BY_HOP || next == NEXT_ROUTING || next == NEXT_DESTINATION || next == NEXT_FRAGMENT || next == NEXT_AH || next == NEXT_ESP) {
                if (++extCount > MAX_EXTENSION_HEADERS) return null

                when (next) {
                    NEXT_FRAGMENT -> {
                        // Fragment header is 8 bytes. We reject fragments rather than
                        // guessing reassembly state in the VPN forwarding engine.
                        if (offset + 8 > total) return null
                        return null
                    }
                    NEXT_ESP -> return null
                    NEXT_AH -> {
                        if (offset + 2 > total) return null
                        val following = packet[offset].toInt() and 0xFF
                        val payloadLenUnits = packet[offset + 1].toInt() and 0xFF
                        val len = (payloadLenUnits + 2) * 4
                        if (len < 8 || offset + len > total) return null
                        offset += len
                        extBytes += len
                        next = following
                    }
                    else -> {
                        if (offset + 2 > total) return null
                        val following = packet[offset].toInt() and 0xFF
                        val hdrExtLen = packet[offset + 1].toInt() and 0xFF
                        val len = (hdrExtLen + 1) * 8
                        if (offset + len > total) return null
                        offset += len
                        extBytes += len
                        next = following
                    }
                }

                if (extBytes > MAX_EXTENSION_BYTES) return null
            }

            if (next != PROTOCOL_TCP && next != PROTOCOL_UDP && next != PROTOCOL_ICMPV6) return null

            val hop = packet[7].toInt() and 0xFF
            val src = try { InetAddress.getByAddress(packet.copyOfRange(8, 24)) } catch (_: Exception) { return null }
            val dst = try { InetAddress.getByAddress(packet.copyOfRange(24, 40)) } catch (_: Exception) { return null }
            return IPv6Header(payloadLength, total, next, hop, src, dst, offset)
        }
    }
}
