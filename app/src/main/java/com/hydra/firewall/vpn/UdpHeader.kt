package com.hydra.firewall.vpn

/**
 * V1.1 - Solo lectura. Extrae puertos y longitud del payload UDP.
 * No hay sesión UDP con estado en V1.1 (eso es V1.4 según el plan acordado);
 * solo se usa para detectar "primera vez visto" (ver SessionTable) y loguear.
 */
data class UdpHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val payloadLength: Int
) {
    companion object {
        /**
         * Corrección de auditoría: udpLength viene del propio paquete (no confiable
         * por sí solo) y debe validarse. Antes se aceptaba cualquier valor y se
         * calculaba payloadLength = udpLength - 8 sin chequear nada, permitiendo
         * que un paquete de 100 bytes declarara un payload de ~5000 bytes.
         *
         * Ahora se valida contra dos límites:
         *   1. udpLength >= 8 (la propia cabecera UDP mínima)
         *   2. udpLength <= ipTotalLength - ipHeaderLength (el espacio real
         *      disponible según lo que el propio IPv4Header ya validó contra
         *      packet.size, no solo contra el tamaño físico leído del TUN)
         */
        fun parse(packet: ByteArray, ipHeaderLength: Int, ipTotalLength: Int): UdpHeader? {
            if (packet.size < ipHeaderLength + 8) return null

            val o = ipHeaderLength
            val sourcePort = ((packet[o].toInt() and 0xFF) shl 8) or (packet[o + 1].toInt() and 0xFF)
            val destPort = ((packet[o + 2].toInt() and 0xFF) shl 8) or (packet[o + 3].toInt() and 0xFF)
            val udpLength = ((packet[o + 4].toInt() and 0xFF) shl 8) or (packet[o + 5].toInt() and 0xFF)

            val maxAvailable = ipTotalLength - ipHeaderLength
            if (udpLength < 8) return null
            if (udpLength > maxAvailable) return null
            if (ipHeaderLength + udpLength > packet.size) return null
            // Destination port 0 is reserved and not usable as an application UDP endpoint.
            if (destPort == 0) return null

            val payloadLength = udpLength - 8

            return UdpHeader(
                sourcePort = sourcePort,
                destinationPort = destPort,
                payloadLength = payloadLength
            )
        }
    }
}
