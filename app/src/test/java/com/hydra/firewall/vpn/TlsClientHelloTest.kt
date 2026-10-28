package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsClientHelloTest {
    @Test
    fun parsesSniCiphersExtensionsGroupsAlpnAndVersions() {
        val raw = WireBuilders.clientHello()
        val info = TlsClientHello.tryParse(raw)!!
        assertEquals("example.com", info.sni)
        assertEquals(0x0303, info.handshakeVersion)
        assertEquals(0x0301, info.recordVersion)
        assertEquals(listOf(0xC02F, 0x1301), info.cipherSuites)
        assertEquals(listOf(0x0000, 0x000A, 0x000B, 0x0010, 0x002B), info.extensions)
        assertEquals(listOf(29, 23, 24), info.ellipticCurves)
        assertEquals(listOf(0), info.ecPointFormats)
        assertEquals(listOf("h2", "http/1.1"), info.alpn)
        assertEquals(listOf(0x0304, 0x0303), info.supportedVersions)
        assertEquals(raw.size, info.bytesConsumed)
    }

    @Test
    fun helloWithoutSniStillParses() {
        val info = TlsClientHello.tryParse(WireBuilders.clientHello(WireBuilders.Hello(sni = null)))!!
        assertNull(info.sni)
        assertFalse(info.extensions.contains(0))
    }

    @Test
    fun incompleteRecordReturnsNullUntilAllBytesArrive() {
        val raw = WireBuilders.clientHello()
        for (cut in listOf(0, 3, 4, 5, 20, raw.size - 1)) assertNull("cortado en $cut", TlsClientHello.tryParse(raw.copyOf(cut)))
        assertEquals("example.com", TlsClientHello.tryParse(raw)!!.sni)
    }

    @Test
    fun trailingBytesAfterTheRecordAreIgnoredButReported() {
        val raw = WireBuilders.clientHello()
        val info = TlsClientHello.tryParse(raw + ByteArray(10) { 7 })!!
        assertEquals(raw.size, info.bytesConsumed)
    }

    @Test
    fun nonHandshakeAndNonClientHelloReturnNull() {
        assertNull(TlsClientHello.tryParse("GET / HTTP/1.1\r\nHost: a\r\n\r\n".toByteArray()))
        val serverHello = WireBuilders.clientHello().also { it[5] = 0x02 }
        assertNull(TlsClientHello.tryParse(serverHello))
        val appData = WireBuilders.clientHello().also { it[0] = 0x17 }
        assertNull(TlsClientHello.tryParse(appData))
    }

    @Test
    fun looksLikeTlsRecordIsCheapAndConservative() {
        assertTrue(TlsClientHello.looksLikeTlsRecord(ByteArray(0)))              // aún no hay datos: no descartar
        assertTrue(TlsClientHello.looksLikeTlsRecord(byteArrayOf(0x16, 0x03, 0x01)))
        assertTrue(TlsClientHello.looksLikeTlsRecord(byteArrayOf(0x16, 0x03, 0x04)))
        assertFalse(TlsClientHello.looksLikeTlsRecord("GET".toByteArray()))
        assertFalse(TlsClientHello.looksLikeTlsRecord(byteArrayOf(0x16, 0x02, 0x00)))
        assertFalse(TlsClientHello.looksLikeTlsRecord(byteArrayOf(0x17, 0x03, 0x03)))
    }

    @Test
    fun oddCipherSuiteLengthIsRejected() {
        val raw = WireBuilders.clientHello()
        // posición de la longitud de cipher suites: 5 (record) + 4 (hs hdr) + 2 (ver) + 32 (random) + 1 (sid len)
        val off = 5 + 4 + 2 + 32 + 1
        raw[off] = 0; raw[off + 1] = 3
        assertNull(TlsClientHello.tryParse(raw))
    }

    @Test
    fun neverThrowsOnRandomOrMutatedInput() {
        val rnd = java.util.Random(7)
        val base = WireBuilders.clientHello()
        repeat(3000) {
            val m = base.copyOf()
            repeat(1 + rnd.nextInt(4)) { m[rnd.nextInt(m.size)] = rnd.nextInt(256).toByte() }
            TlsClientHello.tryParse(m)
            val junk = ByteArray(rnd.nextInt(200)).also { rnd.nextBytes(it) }
            TlsClientHello.tryParse(junk)
        }
    }

    @Test
    fun truncatedExtensionLengthDoesNotLeakGarbageOrCrash() {
        val raw = WireBuilders.clientHello(WireBuilders.Hello(sni = "a.com", groups = null, pointFormats = null, alpn = null, supportedVersions = null))
        // corromper la longitud de la extensión SNI para que exceda el bloque de extensiones
        val extBlock = raw.size - (2 + 2 + 2 + 2 + 3 + "a.com".length)   // inicio del primer extension header
        raw[extBlock + 2] = 0x7F; raw[extBlock + 3] = 0x7F
        val info = TlsClientHello.tryParse(raw)
        assertTrue(info == null || info.sni == null)
    }
}
