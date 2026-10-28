package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsMessageValidatorTest {
    @Test
    fun validQueryIsAcceptedAndNameIsLowercased() {
        val q = WireBuilders.dnsQuery("Ads.Example.COM")
        assertTrue(DnsMessageValidator.isQuery(q))
        assertFalse(DnsMessageValidator.isResponse(q))
        assertEquals("ads.example.com", DnsMessageValidator.extractQueryName(q))
    }

    @Test
    fun acceptsUpToSixteenQuestionsButNotMore() {
        assertTrue(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qd = 2)))
        assertTrue(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qd = 16)))
        assertFalse(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qd = 17)))
        assertFalse(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qd = 0)))
    }

    @Test
    fun rejectsResponsesOpcodesAndZeroTypeOrClass() {
        val q = WireBuilders.dnsQuery("a.com")
        val asResponse = q.copyOf().also { it[2] = (it[2].toInt() or 0x80).toByte() }
        assertFalse(DnsMessageValidator.isQuery(asResponse))
        assertTrue(DnsMessageValidator.isResponse(asResponse))

        val inverseQuery = q.copyOf().also { it[2] = (it[2].toInt() or (1 shl 3)).toByte() }   // opcode 1
        assertFalse(DnsMessageValidator.isQuery(inverseQuery))

        assertFalse(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qtype = 0)))
        assertFalse(DnsMessageValidator.isQuery(WireBuilders.dnsQuery("a.com", qclass = 0)))
    }

    @Test
    fun rejectsTruncatedAndOversizedMessages() {
        val q = WireBuilders.dnsQuery("example.com")
        assertFalse(DnsMessageValidator.isQuery(ByteArray(0)))
        assertFalse(DnsMessageValidator.isQuery(ByteArray(11)))
        for (cut in 12 until q.size) assertFalse("cortado en $cut", DnsMessageValidator.isQuery(q.copyOf(cut)))
        assertFalse(DnsMessageValidator.isQuery(ByteArray(65536)))
    }

    @Test
    fun rejectsLabelsLongerThan63AndNamesWithTooManyLabels() {
        val longLabel = "a".repeat(64) + ".com"
        assertFalse(DnsMessageValidator.isQuery(WireBuilders.dnsQuery(longLabel)))
        assertNull(DnsMessageValidator.extractQueryName(WireBuilders.dnsQuery(longLabel)))
        val manyLabels = (1..200).joinToString(".") { "a" }
        assertNull(DnsMessageValidator.extractQueryName(WireBuilders.dnsQuery(manyLabels)))
    }

    @Test
    fun compressionPointerInFirstQuestionIsNotFollowed() {
        val q = WireBuilders.dnsQuery("a.com")
        val withPointer = q.copyOf().also { it[12] = 0xC0.toByte(); it[13] = 12 }
        assertNull(DnsMessageValidator.extractQueryName(withPointer))
    }

    @Test
    fun emptyNameHasNoQueryName() {
        val rootOnly = WireBuilders.dnsQuery("")
        assertNull(DnsMessageValidator.extractQueryName(rootOnly))
    }

    @Test
    fun extractQueryNameNeverThrowsOnGarbage() {
        val rnd = java.util.Random(42)
        repeat(2000) {
            val n = rnd.nextInt(80)
            val bytes = ByteArray(n).also { rnd.nextBytes(it) }
            DnsMessageValidator.isQuery(bytes)
            DnsMessageValidator.isResponse(bytes)
            DnsMessageValidator.extractQueryName(bytes)
        }
    }
}
