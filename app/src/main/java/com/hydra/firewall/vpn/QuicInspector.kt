package com.hydra.firewall.vpn

/** Lightweight QUIC/HTTP3 classifier. It never decrypts traffic. */
object QuicInspector {
    data class Info(val isQuic: Boolean, val isLongHeader: Boolean, val version: Long, val isInitial: Boolean, val dcidLength: Int)

    fun inspect(payload: ByteArray): Info {
        if (payload.size < 1) return Info(false, false, 0, false, 0)
        val first = payload[0].toInt() and 0xFF
        if ((first and 0x40) == 0) return Info(false, false, 0, false, 0)
        val longHeader = (first and 0x80) != 0
        if (!longHeader) return Info(true, false, 0, false, 0)
        if (payload.size < 6) return Info(true, true, 0, false, 0)
        val version = u32(payload, 1)
        val packetType = (first ushr 4) and 0x03
        val dcidLen = payload[5].toInt() and 0xFF
        return Info(true, true, version, packetType == 0, dcidLen)
    }

    private fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xff) shl 24) or
            ((b[off + 1].toLong() and 0xff) shl 16) or
            ((b[off + 2].toLong() and 0xff) shl 8) or
            (b[off + 3].toLong() and 0xff)
}
