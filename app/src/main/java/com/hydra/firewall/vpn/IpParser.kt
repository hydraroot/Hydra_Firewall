package com.hydra.firewall.vpn

import java.util.concurrent.atomic.AtomicLong

/**
 * Punto de entrada del parseo. Decide IPv4 vs IPv6 vs otro.
 *
 * IPv6 soporta TCP/UDP/ICMPv6 con validación de checksum; encabezados de extensión comunes son parseados y los fragmentos IPv6 se reensamblan con límites estrictos.
 */
object IpParser {

    // Contadores agregados, expuestos para la pantalla de diagnóstico.
    val ipv4Count = AtomicLong(0)
    val ipv6Count = AtomicLong(0)
    val ipv6UnsupportedCount = AtomicLong(0)
    val malformedCount = AtomicLong(0)
    val ipv6ChecksumErrorCount = AtomicLong(0)
    val fragmentedIpv4Count = AtomicLong(0)
    val fragmentedIpv6Count = AtomicLong(0)
    val ipv6FragmentReassembler = Ipv6FragmentReassembler()

    sealed class Result {
        data class Ipv4(val header: IPv4Header) : Result()
        data class Icmpv4(val packet: ByteArray, val header: IPv4Header, val type: Int, val code: Int) : Result()
        data class Ipv6Unsupported(val rawVersionByte: Int) : Result()
        data class Ipv6ChecksumInvalid(val header: IPv6Header) : Result()
        data class Ipv6(val packet: ByteArray, val header: IPv6Header) : Result()
        data class Icmpv6(val packet: ByteArray, val header: IPv6Header, val type: Int, val code: Int) : Result()
        object Malformed : Result()
    }

    fun parse(packet: ByteArray): Result {
        if (packet.isEmpty()) {
            malformedCount.incrementAndGet()
            return Result.Malformed
        }

        val versionAndIhl = packet[0].toInt() and 0xFF
        val ipVersion = versionAndIhl ushr 4

        return when (ipVersion) {
            4 -> {
                val header = IPv4Header.parse(packet)
                if (header == null) {
                    malformedCount.incrementAndGet()
                    Result.Malformed
                } else {
                    ipv4Count.incrementAndGet()
                    if (header.protocol == IPv4Header.PROTOCOL_ICMP &&
                        packet.size >= header.headerLength + 2) {
                        val type = packet[header.headerLength].toInt() and 0xFF
                        val code = packet[header.headerLength + 1].toInt() and 0xFF
                        Result.Icmpv4(packet, header, type, code)
                    } else {
                        Result.Ipv4(header)
                    }
                }
            }
            6 -> {
                val maybeReassembled = ipv6FragmentReassembler.accept(packet)
                if (maybeReassembled == null && IPv6Header.hasFragmentHeader(packet)) {
                    ipv6UnsupportedCount.incrementAndGet()
                    fragmentedIpv6Count.incrementAndGet()
                    return Result.Ipv6Unsupported(ipVersion)
                }
                val effectivePacket = maybeReassembled ?: packet
                val header = IPv6Header.parse(effectivePacket)
                if (header == null) {
                    ipv6UnsupportedCount.incrementAndGet()
                    Result.Ipv6Unsupported(ipVersion)
                } else {
                    ipv6Count.incrementAndGet()
                    if (!Ipv6TransportChecksum.isValid(effectivePacket, header)) {
                        ipv6ChecksumErrorCount.incrementAndGet()
                        Result.Ipv6ChecksumInvalid(header)
                    } else if (header.nextHeader == IPv6Header.PROTOCOL_ICMPV6 && effectivePacket.size >= header.headerLength + 2) {
                        val type = effectivePacket[header.headerLength].toInt() and 0xFF
                        val code = effectivePacket[header.headerLength + 1].toInt() and 0xFF
                        Result.Icmpv6(effectivePacket, header, type, code)
                    } else {
                        Result.Ipv6(effectivePacket, header)
                    }
                }
            }
            else -> {
                malformedCount.incrementAndGet()
                Result.Malformed
            }
        }
    }
}
