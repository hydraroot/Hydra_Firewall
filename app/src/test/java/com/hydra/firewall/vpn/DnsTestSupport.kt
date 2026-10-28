package com.hydra.firewall.vpn

import java.io.ByteArrayOutputStream

/** Constructores de mensajes DNS / TLS para tests (no forman parte de la app). */
internal object WireBuilders {
    fun dnsQuery(name: String, qtype: Int = 1, id: Int = 0x1234, rd: Boolean = true, qd: Int = 1, qclass: Int = 1): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(id ushr 8); o.write(id and 0xFF)
        val flags = if (rd) 0x0100 else 0
        o.write(flags ushr 8); o.write(flags and 0xFF)
        o.write(0); o.write(qd)
        o.write(0); o.write(0); o.write(0); o.write(0); o.write(0); o.write(0)
        repeat(qd) {
            for (label in name.split('.').filter { it.isNotEmpty() }) {
                val b = label.toByteArray(Charsets.ISO_8859_1)
                o.write(b.size); o.write(b)
            }
            o.write(0)
            o.write(qtype ushr 8); o.write(qtype and 0xFF)
            o.write(qclass ushr 8); o.write(qclass and 0xFF)
        }
        return o.toByteArray()
    }

    private fun u16(o: ByteArrayOutputStream, v: Int) { o.write((v ushr 8) and 0xFF); o.write(v and 0xFF) }

    class Hello(
        val handshakeVersion: Int = 0x0303,
        val ciphers: List<Int> = listOf(0xC02F, 0x1301),
        val sni: String? = "example.com",
        val groups: List<Int>? = listOf(29, 23, 24),
        val pointFormats: List<Int>? = listOf(0),
        val alpn: List<String>? = listOf("h2", "http/1.1"),
        val supportedVersions: List<Int>? = listOf(0x0304, 0x0303),
        val extraExtensionsFirst: List<Int> = emptyList(),
        val recordVersion: Int = 0x0301
    )

    fun clientHello(h: Hello = Hello()): ByteArray {
        val exts = ByteArrayOutputStream()
        fun ext(type: Int, body: ByteArray) { u16(exts, type); u16(exts, body.size); exts.write(body) }
        for (t in h.extraExtensionsFirst) ext(t, ByteArray(0))
        h.sni?.let { name ->
            val n = name.toByteArray()
            val b = ByteArrayOutputStream()
            u16(b, n.size + 3); b.write(0); u16(b, n.size); b.write(n)
            ext(0x0000, b.toByteArray())
        }
        h.groups?.let { g ->
            val b = ByteArrayOutputStream(); u16(b, g.size * 2); g.forEach { u16(b, it) }; ext(0x000A, b.toByteArray())
        }
        h.pointFormats?.let { p ->
            val b = ByteArrayOutputStream(); b.write(p.size); p.forEach { b.write(it) }; ext(0x000B, b.toByteArray())
        }
        h.alpn?.let { list ->
            val inner = ByteArrayOutputStream()
            list.forEach { val s = it.toByteArray(); inner.write(s.size); inner.write(s) }
            val b = ByteArrayOutputStream(); u16(b, inner.size()); b.write(inner.toByteArray()); ext(0x0010, b.toByteArray())
        }
        h.supportedVersions?.let { v ->
            val b = ByteArrayOutputStream(); b.write(v.size * 2); v.forEach { u16(b, it) }; ext(0x002B, b.toByteArray())
        }

        val body = ByteArrayOutputStream()
        u16(body, h.handshakeVersion)
        body.write(ByteArray(32) { it.toByte() })          // random
        body.write(0)                                      // session id len
        u16(body, h.ciphers.size * 2); h.ciphers.forEach { u16(body, it) }
        body.write(1); body.write(0)                       // compression: null
        u16(body, exts.size()); body.write(exts.toByteArray())

        val hs = ByteArrayOutputStream()
        hs.write(0x01)                                     // ClientHello
        hs.write((body.size() ushr 16) and 0xFF); hs.write((body.size() ushr 8) and 0xFF); hs.write(body.size() and 0xFF)
        hs.write(body.toByteArray())

        val rec = ByteArrayOutputStream()
        rec.write(0x16); u16(rec, h.recordVersion); u16(rec, hs.size()); rec.write(hs.toByteArray())
        return rec.toByteArray()
    }
}
