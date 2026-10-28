package com.hydra.firewall.vpn

/**
 * V1.1 - Solo lectura. Esta clase NO genera paquetes TCP, NO mantiene estado
 * de conexión, NO abre sockets. Únicamente interpreta la cabecera que llegó
 * del TUN, incluyendo las opciones (MSS, Window Scale) porque el motor TCP las va a
 * necesitar y así evitamos retocar este parser después.
 *
 * Prohibido explícitamente en V1.1 (condición 1 del contrato de implementación):
 * nada de Socket, connect(), forwarding, SYN/ACK, máquina de estados.
 */
data class TcpHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgmentNumber: Long,
    val headerLength: Int,
    val flags: Int,
    val window: Int,
    val mss: Int?,        // null si la opción no estaba presente
    val windowScale: Int? // null si la opción no estaba presente
) {
    val isFin: Boolean get() = (flags and FLAG_FIN) != 0
    val isSyn: Boolean get() = (flags and FLAG_SYN) != 0
    val isRst: Boolean get() = (flags and FLAG_RST) != 0
    val isPsh: Boolean get() = (flags and FLAG_PSH) != 0
    val isAck: Boolean get() = (flags and FLAG_ACK) != 0

    companion object {
        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_PSH = 0x08
        const val FLAG_ACK = 0x10
        const val FLAG_URG = 0x20

        private const val OPT_END = 0
        private const val OPT_NOP = 1
        private const val OPT_MSS = 2
        private const val OPT_WINDOW_SCALE = 3

        /**
         * Corrección de auditoría: antes solo se validaba contra packet.size
         * (el tamaño físico del buffer leído del TUN), no contra el límite real
         * declarado por IPv4Header.totalLength. Si packet.size > ipTotalLength
         * (padding de capa de enlace, por ejemplo), el parser podía interpretar
         * bytes posteriores al paquete IPv4 real como cabecera u opciones TCP.
         * Ahora el límite efectivo de lectura es ipEnd = ipTotalLength, nunca
         * packet.size directamente.
         */
        fun parse(packet: ByteArray, ipHeaderLength: Int, ipTotalLength: Int): TcpHeader? {
            val ipEnd = ipTotalLength
            if (ipEnd > packet.size) return null
            if (ipHeaderLength + 20 > ipEnd) return null

            val o = ipHeaderLength

            val sourcePort = ((packet[o].toInt() and 0xFF) shl 8) or (packet[o + 1].toInt() and 0xFF)
            val destPort = ((packet[o + 2].toInt() and 0xFF) shl 8) or (packet[o + 3].toInt() and 0xFF)

            val seq = readUInt32(packet, o + 4)
            val ack = readUInt32(packet, o + 8)

            val dataOffsetByte = packet[o + 12].toInt() and 0xFF
            val dataOffset = (dataOffsetByte ushr 4) and 0x0F
            val headerLength = dataOffset * 4
            if (headerLength < 20 || ipHeaderLength + headerLength > ipEnd) return null

            val flags = packet[o + 13].toInt() and 0x3F
            val window = ((packet[o + 14].toInt() and 0xFF) shl 8) or (packet[o + 15].toInt() and 0xFF)

            var mss: Int? = null
            var windowScale: Int? = null

            // recorrer desde el final de la cabecera fija (byte 20) hasta headerLength,
            // interpretando kind/length de cada opción. optEnd ahora está acotado
            // por ipEnd, no por packet.size.
            var optOffset = o + 20
            val optEnd = o + headerLength
            while (optOffset < optEnd) {
                val kind = packet[optOffset].toInt() and 0xFF
                when (kind) {
                    OPT_END -> break
                    OPT_NOP -> optOffset += 1
                    OPT_MSS -> {
                        if (optOffset + 3 < optEnd) {
                            mss = ((packet[optOffset + 2].toInt() and 0xFF) shl 8) or
                                    (packet[optOffset + 3].toInt() and 0xFF)
                        }
                        val len = if (optOffset + 1 < optEnd) packet[optOffset + 1].toInt() and 0xFF else 4
                        optOffset += if (len >= 2) len else 4
                    }
                    OPT_WINDOW_SCALE -> {
                        if (optOffset + 2 < optEnd) {
                            windowScale = packet[optOffset + 2].toInt() and 0xFF
                        }
                        val len = if (optOffset + 1 < optEnd) packet[optOffset + 1].toInt() and 0xFF else 3
                        optOffset += if (len >= 2) len else 3
                    }
                    else -> {
                        val len = if (optOffset + 1 < optEnd) packet[optOffset + 1].toInt() and 0xFF else 1
                        optOffset += if (len >= 2) len else 1
                    }
                }
            }

            return TcpHeader(
                sourcePort = sourcePort,
                destinationPort = destPort,
                sequenceNumber = seq,
                acknowledgmentNumber = ack,
                headerLength = headerLength,
                flags = flags,
                window = window,
                mss = mss,
                windowScale = windowScale
            )
        }

        private fun readUInt32(packet: ByteArray, offset: Int): Long {
            return ((packet[offset].toLong() and 0xFF) shl 24) or
                    ((packet[offset + 1].toLong() and 0xFF) shl 16) or
                    ((packet[offset + 2].toLong() and 0xFF) shl 8) or
                    (packet[offset + 3].toLong() and 0xFF)
        }
    }
}
