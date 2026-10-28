package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class InternetChecksumTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun matchesRfc1071Example() {
        // RFC 1071 §3: 00 01 f2 03 f4 f5 f6 f7 -> suma 0xddf2, checksum 0x220d
        val data = bytes(0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7)
        assertEquals(0xDDF2, InternetChecksum.compute(data))
        assertEquals(0x220D, InternetChecksum.checksum(data))
    }

    @Test
    fun oddLengthPadsWithZeroOnTheRight() {
        assertEquals(0x1234 + 0x5600, InternetChecksum.compute(bytes(0x12, 0x34, 0x56)))
    }

    @Test
    fun verifyingAValidPacketGivesAllOnes() {
        // IPv4 de ejemplo con checksum correcto (cabecera de 20 bytes): la suma incluyendo el checksum es 0xFFFF
        val hdr = bytes(0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7)
        val ck = InternetChecksum.checksum(hdr)
        assertEquals(0xB861, ck)                                   // valor conocido del ejemplo clásico
        hdr[10] = (ck ushr 8).toByte(); hdr[11] = ck.toByte()
        assertEquals(0xFFFF, InternetChecksum.compute(hdr))
    }

    @Test
    fun addAccumulatesAcrossChunksLikeASingleCall() {
        val data = ByteArray(101) { (it * 37 + 11).toByte() }
        val whole = InternetChecksum.compute(data)
        var acc = InternetChecksum.add(0, data, 0, 40)              // 40 bytes: longitud par
        acc = InternetChecksum.add(acc, data, 40, 61)
        assertEquals(whole, acc)
    }

    @Test
    fun offsetAndLengthSelectOnlyThatRange() {
        val data = bytes(0xFF, 0xFF, 0x12, 0x34, 0xFF, 0xFF)
        assertEquals(0x1234, InternetChecksum.compute(data, 2, 2))
        assertEquals(0, InternetChecksum.compute(data, 2, 0))
    }

    @Test
    fun invalidRangesAreRejected() {
        val data = ByteArray(4)
        for ((o, l) in listOf(-1 to 2, 0 to -1, 3 to 2, 5 to 0)) {
            try { InternetChecksum.compute(data, o, l); fail("rango inválido $o,$l") } catch (e: IllegalArgumentException) { /* ok */ }
        }
        assertTrue(true)
    }
}
