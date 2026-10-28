package com.hydra.firewall.vpn

/** Conservative QUIC detector used for diagnostics/policy labeling; it never overrides UDP policy. */
object QuicDetector {
    fun isLikelyQuicUdp(payload: ByteArray, destinationPort: Int): Boolean {
        if (destinationPort != 443 || payload.isEmpty()) return false
        val first = payload[0].toInt() and 0xFF
        // QUIC fixed bit must be 1. Long headers also have bit 7 set.
        if ((first and 0x40) == 0) return false
        if ((first and 0x80) != 0) return payload.size >= 6
        // Short header: enough data to carry protected packet payload.
        return payload.size >= 2
    }
}
