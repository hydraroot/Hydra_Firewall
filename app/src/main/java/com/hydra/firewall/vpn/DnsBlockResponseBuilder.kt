package com.hydra.firewall.vpn

/**
 * Builds a synthetic DNS response for a blocked domain: same transaction ID
 * and question as the original query, with an answer of 0.0.0.0 (A) or ::
 * (AAAA) and a short TTL. This resolves instantly and without retries from
 * the requesting app, unlike NXDOMAIN which many HTTP/networking stacks
 * treat as a transient error and retry aggressively.
 */
object DnsBlockResponseBuilder {
    private const val TTL_SECONDS = 60

    /**
     * [query] must be the original, already-validated DNS query payload.
     * [qtype] is the question's query type (1 = A, 28 = AAAA).
     */
    fun build(query: ByteArray, qtype: Int): ByteArray? {
        if (query.size < 12) return null
        val questionEnd = findQuestionEnd(query) ?: return null
        val questionSection = query.copyOfRange(12, questionEnd)

        val answerRecord = when (qtype) {
            1 -> buildAnswer(type = 1, rdata = byteArrayOf(0, 0, 0, 0))
            28 -> buildAnswer(type = 28, rdata = ByteArray(16)) // ::
            else -> null // Other qtypes get NXDOMAIN instead, below.
        }

        val out = java.io.ByteArrayOutputStream(query.size + 32)
        // Header: same transaction ID as the query.
        out.write(query[0].toInt()); out.write(query[1].toInt())
        // Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD copied from query,
        // RA=1, RCODE = 0 (NOERROR) when we answer, 3 (NXDOMAIN) otherwise.
        val queryFlags = ((query[2].toInt() and 0xFF) shl 8) or (query[3].toInt() and 0xFF)
        val rd = queryFlags and 0x0100
        val rcode = if (answerRecord != null) 0 else 3
        val respFlags = 0x8000 or rd or 0x0080 or rcode
        out.write((respFlags ushr 8) and 0xFF); out.write(respFlags and 0xFF)
        // QDCOUNT = 1
        out.write(0x00); out.write(0x01)
        // ANCOUNT
        val anCount = if (answerRecord != null) 1 else 0
        out.write(0x00); out.write(anCount)
        // NSCOUNT, ARCOUNT = 0
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        // Question section, copied verbatim.
        out.write(questionSection)
        if (answerRecord != null) out.write(answerRecord)
        return out.toByteArray()
    }

    private fun buildAnswer(type: Int, rdata: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(12 + rdata.size)
        // Name: compression pointer back to the question name at offset 12.
        out.write(0xC0); out.write(0x0C)
        out.write((type ushr 8) and 0xFF); out.write(type and 0xFF) // TYPE
        out.write(0x00); out.write(0x01) // CLASS = IN
        val ttl = TTL_SECONDS
        out.write((ttl ushr 24) and 0xFF); out.write((ttl ushr 16) and 0xFF)
        out.write((ttl ushr 8) and 0xFF); out.write(ttl and 0xFF)
        out.write((rdata.size ushr 8) and 0xFF); out.write(rdata.size and 0xFF)
        out.write(rdata)
        return out.toByteArray()
    }

    /** Returns the offset right after the single question's QTYPE+QCLASS. */
    private fun findQuestionEnd(data: ByteArray): Int? {
        var off = 12
        var steps = 0
        while (off < data.size) {
            if (++steps > 128) return null
            val len = data[off].toInt() and 0xFF
            if (len == 0) {
                val end = off + 1 + 4
                return if (end <= data.size) end else null
            }
            if ((len and 0xC0) == 0xC0) return null // unexpected in a fresh query
            if (len > 63 || off + 1 + len > data.size) return null
            off += 1 + len
        }
        return null
    }

    /** Reads the first question's QTYPE from an already-validated query. */
    fun readQuestionType(query: ByteArray): Int {
        var off = 12
        var steps = 0
        while (off < query.size) {
            if (++steps > 128) return -1
            val len = query[off].toInt() and 0xFF
            if (len == 0) {
                val typeOff = off + 1
                if (typeOff + 1 >= query.size) return -1
                return ((query[typeOff].toInt() and 0xFF) shl 8) or (query[typeOff + 1].toInt() and 0xFF)
            }
            if ((len and 0xC0) == 0xC0) return -1
            if (len > 63 || off + 1 + len > query.size) return -1
            off += 1 + len
        }
        return -1
    }
}
