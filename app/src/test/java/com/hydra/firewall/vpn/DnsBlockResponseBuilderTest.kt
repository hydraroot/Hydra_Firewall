package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsBlockResponseBuilderTest {
    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    @Test
    fun answersAWithZeroAddressAndKeepsIdQuestionAndRd() {
        val q = WireBuilders.dnsQuery("ads.example.com", qtype = 1, id = 0xBEEF)
        val r = DnsBlockResponseBuilder.build(q, 1)!!
        assertEquals(0xBEEF, u16(r, 0))
        val flags = u16(r, 2)
        assertTrue("QR", flags and 0x8000 != 0)
        assertTrue("RD copiado", flags and 0x0100 != 0)
        assertTrue("RA", flags and 0x0080 != 0)
        assertEquals("NOERROR", 0, flags and 0xF)
        assertEquals(1, u16(r, 4)); assertEquals(1, u16(r, 6)); assertEquals(0, u16(r, 8)); assertEquals(0, u16(r, 10))
        val questionLen = q.size - 12
        assertEquals(q.copyOfRange(12, q.size).toList(), r.copyOfRange(12, 12 + questionLen).toList())
        val ans = 12 + questionLen
        assertEquals(0xC00C, u16(r, ans))            // puntero al nombre
        assertEquals(1, u16(r, ans + 2)); assertEquals(1, u16(r, ans + 4))
        assertEquals(60, (u16(r, ans + 6) shl 16) or u16(r, ans + 8))
        assertEquals(4, u16(r, ans + 10))
        assertEquals(listOf<Byte>(0, 0, 0, 0), r.copyOfRange(ans + 12, ans + 16).toList())
        assertEquals(ans + 16, r.size)
        assertTrue(DnsMessageValidator.isResponse(r))
    }

    @Test
    fun answersAaaaWithSixteenZeroBytes() {
        val q = WireBuilders.dnsQuery("x.test", qtype = 28)
        val r = DnsBlockResponseBuilder.build(q, 28)!!
        val ans = q.size
        assertEquals(28, u16(r, ans + 2))
        assertEquals(16, u16(r, ans + 10))
        assertTrue(r.copyOfRange(ans + 12, ans + 28).all { it == 0.toByte() })
    }

    @Test
    fun otherTypesGetNxdomainWithoutAnswer() {
        val q = WireBuilders.dnsQuery("x.test", qtype = 15)
        val r = DnsBlockResponseBuilder.build(q, 15)!!
        assertEquals(3, u16(r, 2) and 0xF)
        assertEquals(0, u16(r, 6))
        assertEquals(q.size, r.size)
    }

    @Test
    fun rdNotSetInQueryIsNotSetInResponse() {
        val r = DnsBlockResponseBuilder.build(WireBuilders.dnsQuery("a.com", rd = false), 1)!!
        assertEquals(0, u16(r, 2) and 0x0100)
    }

    @Test
    fun malformedQueriesReturnNull() {
        assertNull(DnsBlockResponseBuilder.build(ByteArray(5), 1))
        val q = WireBuilders.dnsQuery("example.com")
        assertNull(DnsBlockResponseBuilder.build(q.copyOf(q.size - 3), 1))     // sin QTYPE/QCLASS completos
        val ptr = q.copyOf().also { it[12] = 0xC0.toByte() }
        assertNull(DnsBlockResponseBuilder.build(ptr, 1))
    }

    @Test
    fun readQuestionTypeParsesOrReturnsMinusOne() {
        assertEquals(1, DnsBlockResponseBuilder.readQuestionType(WireBuilders.dnsQuery("a.com", qtype = 1)))
        assertEquals(28, DnsBlockResponseBuilder.readQuestionType(WireBuilders.dnsQuery("a.com", qtype = 28)))
        assertEquals(-1, DnsBlockResponseBuilder.readQuestionType(ByteArray(12)))
        val ptr = WireBuilders.dnsQuery("a.com").also { it[12] = 0xC0.toByte() }
        assertEquals(-1, DnsBlockResponseBuilder.readQuestionType(ptr))
    }
}
