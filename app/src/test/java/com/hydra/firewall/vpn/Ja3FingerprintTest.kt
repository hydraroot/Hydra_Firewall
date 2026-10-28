package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class Ja3FingerprintTest {
    private fun md5(s: String) = MessageDigest.getInstance("MD5").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }

    private fun info(
        cipherSuites: List<Int>, extensions: List<Int>, curves: List<Int> = emptyList(), points: List<Int> = emptyList(),
        version: Int = 0x0303, alpn: List<String> = emptyList(), supported: List<Int> = emptyList(), sni: String? = null
    ) = TlsClientHello.Info(0x0301, version, sni, cipherSuites, extensions, curves, points, alpn, supported, 0)

    @Test
    fun matchesTheSalesforceReferenceVector() {
        // Ejemplo público del README de JA3: este string da este MD5.
        val r = Ja3Fingerprint.from(info(
            version = 769, cipherSuites = listOf(47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
            extensions = listOf(0, 10, 11), curves = listOf(23, 24, 25), points = listOf(0)
        ))
        assertEquals("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0", r.ja3)
        assertEquals("ada70206e40642a3e4461f35503241d5", r.ja3Hash)
    }

    @Test
    fun greaseValuesAreStrippedSoChromeIsStable() {
        val a = Ja3Fingerprint.from(info(listOf(0x0A0A, 0x1301, 0xC02F), listOf(0x1A1A, 0, 10, 0xFAFA), listOf(0x2A2A, 29), listOf(0)))
        val b = Ja3Fingerprint.from(info(listOf(0xEAEA, 0x1301, 0xC02F), listOf(0x3A3A, 0, 10, 0x4A4A), listOf(0x5A5A, 29), listOf(0)))
        assertEquals(a.ja3, b.ja3)
        assertEquals(a.ja3Hash, b.ja3Hash)
        assertEquals("771,4865-49199,0-10,29,0", a.ja3)
        assertFalse(a.ja3.contains("2570"))      // 0x0A0A
    }

    @Test
    fun ja3nIgnoresExtensionOrderButJa3DoesNot() {
        val a = Ja3Fingerprint.from(info(listOf(1, 2), listOf(0, 10, 11, 16, 43)))
        val b = Ja3Fingerprint.from(info(listOf(1, 2), listOf(43, 16, 11, 10, 0)))
        assertTrue(a.ja3Hash != b.ja3Hash)
        assertEquals(a.ja3nHash, b.ja3nHash)
        assertEquals("771,1-2,0-10-11-16-43,,", a.ja3n)
    }

    @Test
    fun hashesAreMd5OfTheirStrings() {
        val r = Ja3Fingerprint.from(info(listOf(4865, 49199), listOf(0, 16), alpn = listOf("h2"), supported = listOf(0x0304)))
        assertEquals(md5(r.ja3), r.ja3Hash)
        assertEquals(md5(r.ja3n), r.ja3nHash)
        assertEquals(md5(r.hydraLite), r.hydraLiteHash)
        assertEquals(32, r.ja3Hash.length)
    }

    @Test
    fun hydraLiteCapturesVersionCountsAlpnAndSortedLists() {
        val r = Ja3Fingerprint.from(info(listOf(49199, 4865), listOf(16, 0, 43), alpn = listOf("h2", "http/1.1"), supported = listOf(0x0A0A, 0x0304, 0x0303)))
        assertEquals("t13_c2_e3_h2_4865-49199_0-16-43", r.hydraLite)
        assertEquals("h2", r.alpn)
        val noAlpn = Ja3Fingerprint.from(info(listOf(1), listOf(0), version = 0x0303))
        assertEquals("t12_c1_e1_00_1_0", noAlpn.hydraLite)
        val legacy = Ja3Fingerprint.from(info(listOf(1), listOf(0), version = 0x0301))
        assertTrue(legacy.hydraLite.startsWith("t10_"))
        val unknown = Ja3Fingerprint.from(info(listOf(1), listOf(0), version = 0x0200))
        assertTrue(unknown.hydraLite.startsWith("t00_"))
    }

    @Test
    fun endToEndFromARealisticClientHello() {
        val parsed = TlsClientHello.tryParse(WireBuilders.clientHello(WireBuilders.Hello(
            ciphers = listOf(0x0A0A, 0x1301, 0xC02F), extraExtensionsFirst = listOf(0x0A0A, 0x1A1A)
        )))!!
        val r = Ja3Fingerprint.from(parsed)
        assertEquals("771,4865-49199,0-10-11-16-43,29-23-24,0", r.ja3)
        assertEquals("example.com", r.sni)
        assertEquals("h2", r.alpn)
        assertTrue(r.hydraLite.startsWith("t13_c2_e5_h2_"))
    }
}
