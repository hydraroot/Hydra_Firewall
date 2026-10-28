package com.hydra.firewall.vpn

import java.net.InetAddress

/**
 * V1.1 - Solo diagnóstico. Esta clase NO genera paquetes, solo los interpreta.
 *
 * Resultado de parsear la cabecera IPv4 de un paquete leído del TUN.
 * Si el paquete es IPv6, ver IpVersionResult.Unsupported en IpParser.
 */
data class IPv4Header(
    val headerLength: Int, // en bytes (IHL * 4), variable, no asumido en 20
    val totalLength: Int,
    val protocol: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val fragmentOffset: Int,
    val moreFragments: Boolean
) {
    val isFragmented: Boolean get() = fragmentOffset != 0 || moreFragments

    companion object {
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17
        const val PROTOCOL_ICMP = 1

        /**
         * Parsea la cabecera IPv4. Devuelve null si el paquete es demasiado corto
         * o inconsistente (nunca lanza excepción por un paquete malformado).
         */
        fun parse(packet: ByteArray): IPv4Header? {
            if (packet.size < 20) return null

            val versionAndIhl = packet[0].toInt() and 0xFF
            val ihl = versionAndIhl and 0x0F
            val headerLength = ihl * 4
            if (headerLength < 20 || packet.size < headerLength) return null

            val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)

            // Corrección de auditoría: validar totalLength contra el tamaño real
            // del paquete y contra headerLength. Sin esto, un paquete malformado
            // (totalLength inconsistente con lo que realmente llegó) se aceptaba
            // igual, y los parsers posteriores (TCP/UDP) terminaban leyendo más
            // allá de los datos válidos o interpretando basura como payload.
            if (totalLength < headerLength || totalLength < 20) return null
            if (totalLength > packet.size) return null

            // IPv4 header checksum must validate before any transport parsing.
            if (InternetChecksum.compute(packet, 0, headerLength) != 0xFFFF) return null

            val fragmentField = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
            val fragmentOffset = fragmentField and 0x1FFF
            val moreFragments = (fragmentField and 0x2000) != 0

            val protocol = packet[9].toInt() and 0xFF

            val srcBytes = byteArrayOf(packet[12], packet[13], packet[14], packet[15])
            val dstBytes = byteArrayOf(packet[16], packet[17], packet[18], packet[19])

            val srcAddr = try {
                InetAddress.getByAddress(srcBytes)
            } catch (e: Exception) {
                return null
            }
            val dstAddr = try {
                InetAddress.getByAddress(dstBytes)
            } catch (e: Exception) {
                return null
            }

            return IPv4Header(
                headerLength = headerLength,
                totalLength = totalLength,
                protocol = protocol,
                sourceAddress = srcAddr,
                destinationAddress = dstAddr,
                fragmentOffset = fragmentOffset,
                moreFragments = moreFragments
            )
        }
    }
}
