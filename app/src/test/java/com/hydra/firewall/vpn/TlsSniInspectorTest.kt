package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TlsSniInspectorTest {
    private fun feedInChunks(hello: ByteArray, chunk: Int): TlsSniInspector.Result? {
        val acc = TlsSniInspector.Accumulator()
        var result: TlsSniInspector.Result? = null
        var i = 0
        while (i < hello.size) {
            val end = minOf(hello.size, i + chunk)
            result = TlsSniInspector.feed(acc, hello.copyOfRange(i, end)) ?: result
            i = end
        }
        return result
    }

    @Test fun normalHelloIsParsedAcrossSegments() {
        val r = feedInChunks(WireBuilders.clientHello(), 100)
        assertNotNull(r)
        assertEquals("example.com", r!!.sni)
    }

    @Test fun paddedHelloOver8KbStillYieldsSni() {
        // ~12 KB de ALPN: antes el inspector se rendía a los 8 KB y el SNI no se leía (evasión del bloqueo por SNI).
        val padded = WireBuilders.clientHello(WireBuilders.Hello(sni = "ads.example.net", alpn = List(60) { "x".repeat(200) }))
        assertEquals(true, padded.size in 9_000..16_000)
        val r = feedInChunks(padded, 1400)
        assertNotNull(r)
        assertEquals("ads.example.net", r!!.sni)
    }

    @Test fun nonTlsTrafficGivesUpImmediately() {
        val acc = TlsSniInspector.Accumulator()
        assertNull(TlsSniInspector.feed(acc, "GET / HTTP/1.1\r\n".toByteArray()))
        assertEquals(true, acc.gaveUp)
    }
}
