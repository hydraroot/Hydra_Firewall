package com.hydra.firewall.vpn

/** Lightweight bounded DNS wire-format validator for UDP DNS messages. */
object DnsMessageValidator {
    private const val HEADER = 12
    private const val MAX_NAME_STEPS = 128

    fun isQuery(message: ByteArray): Boolean {
        if (message.size < HEADER || message.size > 65535) return false
        val flags = u16(message, 2)
        val qr = flags and 0x8000
        val opcode = (flags ushr 11) and 0xF
        val qd = u16(message, 4)
        if (qr != 0 || opcode != 0 || qd < 1 || qd > 16) return false
        var off = HEADER
        repeat(qd) {
            val next = skipName(message, off) ?: return false
            if (next + 4 > message.size) return false
            val qtype = u16(message, next)
            val qclass = u16(message, next + 2)
            if (qtype == 0 || qclass == 0) return false
            off = next + 4
        }
        return true
    }

    fun isResponse(message: ByteArray): Boolean {
        if (message.size < HEADER || message.size > 65535) return false
        val flags = u16(message, 2)
        val qr = flags and 0x8000
        val opcode = (flags ushr 11) and 0xF
        return qr != 0 && opcode == 0 && u16(message, 4) > 0
    }

    /**
     * Extracts the first question's domain name from a DNS query message,
     * lowercased, without the trailing root dot (e.g. "ads.example.com").
     * Call only after [isQuery] has already validated the message structure;
     * this re-walks the name with the same bounds but does not repeat every
     * header check. Returns null on any malformed or oversized label,
     * mirroring the safety bounds in [skipName].
     */
    fun extractQueryName(message: ByteArray): String? {
        if (message.size < HEADER) return null
        val qd = u16(message, 4)
        if (qd < 1) return null
        val sb = StringBuilder()
        var off = HEADER
        var steps = 0
        while (off < message.size) {
            if (++steps > MAX_NAME_STEPS) return null
            val len = message[off].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) {
                // A compression pointer this early (first question of a
                // freshly-built query) is unusual; treat as unresolvable
                // rather than following the pointer, to keep this bounded
                // and side-effect-free.
                return null
            }
            if (len > 63 || off + 1 + len > message.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until len) {
                val c = message[off + 1 + i].toInt().toChar()
                sb.append(c)
            }
            off += 1 + len
        }
        if (sb.isEmpty()) return null
        return sb.toString().lowercase()
    }

    private fun skipName(data: ByteArray, start: Int): Int? {
        var off = start
        var steps = 0
        while (off < data.size) {
            if (++steps > MAX_NAME_STEPS) return null
            val len = data[off].toInt() and 0xFF
            if (len == 0) return off + 1
            if ((len and 0xC0) == 0xC0) {
                if (off + 1 >= data.size) return null
                val ptr = ((len and 0x3F) shl 8) or (data[off + 1].toInt() and 0xFF)
                if (ptr >= data.size) return null
                // A pointer terminates the name at the current location.
                return off + 2
            }
            if (len > 63 || off + 1 + len > data.size) return null
            off += 1 + len
        }
        return null
    }

    private fun u16(d: ByteArray, o: Int): Int =
        ((d[o].toInt() and 0xFF) shl 8) or (d[o + 1].toInt() and 0xFF)
}
