package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsWireParserTest {
    private fun header(an: Int) = byteArrayOf(
        0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, an.toByte(), 0, 0, 0, 0
    )

    private val question = byteArrayOf(1, 'a'.code.toByte(), 3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0, 0, 1, 0, 1)

    private fun build(answerName: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(header(1)); o.write(question); o.write(answerName)
        o.write(byteArrayOf(0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4))
        return o.toByteArray()
    }

    @Test
    fun validCompressionPointerIsParsed() {
        val r = DnsWireParser.extractAddressAnswers(build(byteArrayOf(0xC0.toByte(), 12)))
        assertNotNull(r)
        assertEquals("a.com", r!![0].domain)
    }

    @Test
    fun selfReferencingPointerDoesNotCrash() {
        val off = 12 + question.size
        val r = DnsWireParser.extractAddressAnswers(build(byteArrayOf(0xC0.toByte(), off.toByte())))
        assertTrue(r == null || r.isEmpty())
    }

    @Test
    fun forwardPointerIsRejected() {
        val off = 12 + question.size + 2
        val r = DnsWireParser.extractAddressAnswers(build(byteArrayOf(0xC0.toByte(), off.toByte())))
        assertTrue(r == null || r.isEmpty())
    }

    @Test
    fun mutualPointerLoopDoesNotCrash() {
        // Nombre en off: etiqueta "x" + puntero a off (bucle indirecto).
        val off = 12 + question.size
        val name = byteArrayOf(1, 'x'.code.toByte(), 0xC0.toByte(), off.toByte())
        val r = DnsWireParser.extractAddressAnswers(build(name))
        assertTrue(r == null || r.isEmpty())
    }

    @Test
    fun truncatedPointerDoesNotCrash() {
        val b = build(byteArrayOf(0xC0.toByte(), 12))
        val r = DnsWireParser.extractAddressAnswers(b.copyOf(12 + question.size + 1))
        assertTrue(r == null || r.isEmpty())
    }
}
