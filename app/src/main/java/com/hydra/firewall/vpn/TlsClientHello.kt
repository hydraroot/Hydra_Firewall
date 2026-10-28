package com.hydra.firewall.vpn

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal, allocation-light parser for a TLS ClientHello record.
 *
 * This only reads the plaintext record/handshake framing that every TLS
 * client (1.0 through 1.3) sends before encryption starts: record header,
 * handshake header, client_version, random, session id, cipher suites,
 * compression methods and extensions. TLS 1.3 does not encrypt any of this,
 * so it works unmodified against modern clients. If the peer uses Encrypted
 * Client Hello (ECH), the "real" SNI is inside an encrypted payload and only
 * the (often decoy) outer SNI is visible here - that limitation is inherent
 * to operating without root/MITM and is documented rather than worked around.
 */
object TlsClientHello {

    data class Info(
        val recordVersion: Int,
        val handshakeVersion: Int,
        val sni: String?,
        val cipherSuites: List<Int>,
        val extensions: List<Int>,
        val ellipticCurves: List<Int>,
        val ecPointFormats: List<Int>,
        val alpn: List<String>,
        val supportedVersions: List<Int>,
        val bytesConsumed: Int
    )

    private const val CONTENT_TYPE_HANDSHAKE = 0x16
    private const val HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

    /**
     * Attempts to parse a single TLS record containing (all of) a ClientHello
     * from [buf]. Returns null if [buf] does not yet contain a complete
     * ClientHello (caller should buffer more bytes and retry) or if it is
     * clearly not a TLS handshake at all (caller should give up immediately).
     *
     * Throws nothing: any malformed input results in null so callers never
     * need a try/catch around normal traffic that simply isn't TLS.
     */
    fun tryParse(buf: ByteArray): Info? = runCatching { parseInternal(buf) }.getOrNull()

    /** Cheap upfront check so callers can bail out fast on obviously non-TLS traffic. */
    fun looksLikeTlsRecord(buf: ByteArray): Boolean {
        if (buf.size < 3) return true // not enough data yet to decide either way
        val contentType = buf[0].toInt() and 0xFF
        val major = buf[1].toInt() and 0xFF
        val minor = buf[2].toInt() and 0xFF
        return contentType == CONTENT_TYPE_HANDSHAKE && major == 0x03 && minor in 0x00..0x04
    }

    private fun parseInternal(buf: ByteArray): Info? {
        if (buf.size < 5) return null
        val bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN)
        val contentType = bb.get().toInt() and 0xFF
        if (contentType != CONTENT_TYPE_HANDSHAKE) return null
        val recordVersion = (bb.get().toInt() and 0xFF shl 8) or (bb.get().toInt() and 0xFF)
        val recordLen = bb.short.toInt() and 0xFFFF
        if (buf.size < 5 + recordLen) return null // incomplete record, caller should buffer more

        if (bb.remaining() < 4) return null
        val handshakeType = bb.get().toInt() and 0xFF
        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) return null
        val hsLen = ((bb.get().toInt() and 0xFF) shl 16) or ((bb.get().toInt() and 0xFF) shl 8) or (bb.get().toInt() and 0xFF)
        if (bb.remaining() < hsLen) return null

        val handshakeVersion = (bb.get().toInt() and 0xFF shl 8) or (bb.get().toInt() and 0xFF)
        // random: 32 bytes
        if (bb.remaining() < 32) return null
        bb.position(bb.position() + 32)

        // session id
        if (bb.remaining() < 1) return null
        val sessionIdLen = bb.get().toInt() and 0xFF
        if (bb.remaining() < sessionIdLen) return null
        bb.position(bb.position() + sessionIdLen)

        // cipher suites
        if (bb.remaining() < 2) return null
        val cipherSuitesLen = bb.short.toInt() and 0xFFFF
        if (bb.remaining() < cipherSuitesLen || cipherSuitesLen % 2 != 0) return null
        val cipherSuites = ArrayList<Int>(cipherSuitesLen / 2)
        var read = 0
        while (read < cipherSuitesLen) {
            cipherSuites.add(bb.short.toInt() and 0xFFFF)
            read += 2
        }

        // compression methods
        if (bb.remaining() < 1) return null
        val compLen = bb.get().toInt() and 0xFF
        if (bb.remaining() < compLen) return null
        bb.position(bb.position() + compLen)

        var sni: String? = null
        val extensionIds = ArrayList<Int>()
        val curves = ArrayList<Int>()
        val ecPointFormats = ArrayList<Int>()
        val alpn = ArrayList<String>()
        val supportedVersions = ArrayList<Int>()

        if (bb.remaining() >= 2) {
            val extTotalLen = bb.short.toInt() and 0xFFFF
            val extEnd = (bb.position() + extTotalLen).coerceAtMost(bb.limit())
            while (bb.position() + 4 <= extEnd) {
                val extType = bb.short.toInt() and 0xFFFF
                val extLen = bb.short.toInt() and 0xFFFF
                val extStart = bb.position()
                if (extStart + extLen > extEnd) break
                extensionIds.add(extType)
                when (extType) {
                    0x0000 -> { // server_name
                        sni = parseSni(bb, extStart, extLen)
                    }
                    0x000A -> { // supported_groups / elliptic_curves
                        curves.addAll(parseUShortList(bb, extStart, extLen, skipHeaderBytes = 2))
                    }
                    0x000B -> { // ec_point_formats (length-prefixed by 1 byte, not 2)
                        ecPointFormats.addAll(parseUByteList(bb, extStart, extLen, skipHeaderBytes = 1))
                    }
                    0x0010 -> { // ALPN
                        alpn.addAll(parseAlpn(bb, extStart, extLen))
                    }
                    0x002B -> { // supported_versions
                        supportedVersions.addAll(parseUByteVersionList(bb, extStart, extLen))
                    }
                }
                bb.position(extStart + extLen)
            }
        }

        return Info(
            recordVersion = recordVersion,
            handshakeVersion = handshakeVersion,
            sni = sni,
            cipherSuites = cipherSuites,
            extensions = extensionIds,
            ellipticCurves = curves,
            ecPointFormats = ecPointFormats,
            alpn = alpn,
            supportedVersions = supportedVersions,
            bytesConsumed = 5 + recordLen
        )
    }

    private fun parseSni(bb: ByteBuffer, extStart: Int, extLen: Int): String? {
        if (extLen < 5) return null
        val listLen = ((bb.get(extStart).toInt() and 0xFF) shl 8) or (bb.get(extStart + 1).toInt() and 0xFF)
        if (listLen < 3 || extStart + 2 + listLen > extStart + extLen) return null
        val nameType = bb.get(extStart + 2).toInt() and 0xFF
        if (nameType != 0x00) return null // host_name only
        val nameLen = ((bb.get(extStart + 3).toInt() and 0xFF) shl 8) or (bb.get(extStart + 4).toInt() and 0xFF)
        if (extStart + 5 + nameLen > extStart + extLen) return null
        val bytes = ByteArray(nameLen)
        for (i in 0 until nameLen) bytes[i] = bb.get(extStart + 5 + i)
        return String(bytes, Charsets.US_ASCII).lowercase().trim().takeIf { it.isNotEmpty() && it.all { c -> c.code in 0x20..0x7E } }
    }

    private fun parseUShortList(bb: ByteBuffer, extStart: Int, extLen: Int, skipHeaderBytes: Int): List<Int> {
        val out = ArrayList<Int>()
        var pos = extStart + skipHeaderBytes
        val end = extStart + extLen
        while (pos + 2 <= end) {
            out.add(((bb.get(pos).toInt() and 0xFF) shl 8) or (bb.get(pos + 1).toInt() and 0xFF))
            pos += 2
        }
        return out
    }

    private fun parseUByteList(bb: ByteBuffer, extStart: Int, extLen: Int, skipHeaderBytes: Int): List<Int> {
        val out = ArrayList<Int>()
        var pos = extStart + skipHeaderBytes
        val end = extStart + extLen
        while (pos < end) {
            out.add(bb.get(pos).toInt() and 0xFF)
            pos += 1
        }
        return out
    }

    private fun parseUByteVersionList(bb: ByteBuffer, extStart: Int, extLen: Int): List<Int> {
        if (extLen < 1) return emptyList()
        val out = ArrayList<Int>()
        var pos = extStart + 1
        val end = extStart + extLen
        while (pos + 2 <= end) {
            out.add(((bb.get(pos).toInt() and 0xFF) shl 8) or (bb.get(pos + 1).toInt() and 0xFF))
            pos += 2
        }
        return out
    }

    private fun parseAlpn(bb: ByteBuffer, extStart: Int, extLen: Int): List<String> {
        if (extLen < 2) return emptyList()
        val out = ArrayList<String>()
        var pos = extStart + 2
        val end = extStart + extLen
        while (pos < end) {
            val len = bb.get(pos).toInt() and 0xFF
            pos += 1
            if (pos + len > end) break
            val bytes = ByteArray(len)
            for (i in 0 until len) bytes[i] = bb.get(pos + i)
            out.add(String(bytes, Charsets.US_ASCII))
            pos += len
        }
        return out
    }
}
