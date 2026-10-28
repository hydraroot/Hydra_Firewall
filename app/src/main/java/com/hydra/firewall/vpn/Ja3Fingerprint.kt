package com.hydra.firewall.vpn

import java.security.MessageDigest

/**
 * Computes JA3 / JA3N handshake fingerprints from a parsed ClientHello.
 *
 * JA3 (Salesforce, 2017) is the de-facto standard client TLS fingerprint:
 * MD5 of "TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats"
 * using decimal values joined by "-", fields joined by ",". Grease values
 * (0x?A?A, e.g. 0x0A0A, 0x1A1A ... 0xFAFA) are stripped first because
 * Chrome/BoringSSL inject a random one on every handshake purely to force
 * middlebox tolerance, which would otherwise make every Chrome connection
 * fingerprint uniquely instead of consistently.
 *
 * This matters for a firewall because JA3 identifies *what made the TLS
 * connection* (a library/stack fingerprint) independently of which domain
 * or IP it talked to - so it keeps working even if malware/tracking SDKs
 * rotate domains or hide behind CDNs/domain fronting, which a pure
 * SNI/IP blocklist cannot do.
 *
 * We also compute JA3N (extensions sorted, otherwise identical), which is
 * more resistant to extension-order randomization that some stacks
 * (notably modern Chrome/BoringSSL) apply deliberately, and a lightweight
 * "Hydra-lite" style string that additionally captures ALPN and TLS version
 * negotiation-related fields. It intentionally does not claim byte-for-byte
 * compatibility with any published third-party fingerprint spec (that also folds in a SHA256
 * truncation scheme and ordering rules beyond what's needed here); it is
 * documented as Hydra's own scheme, not a claim of compatibility with any external standard.
 */
object Ja3Fingerprint {

    data class Result(
        val ja3: String,
        val ja3Hash: String,
        val ja3n: String,
        val ja3nHash: String,
        val hydraLite: String,
        val hydraLiteHash: String,
        val sni: String?,
        val alpn: String?
    )

    private val GREASE = setOf(
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    )

    fun from(info: TlsClientHello.Info): Result {
        val ciphers = info.cipherSuites.filterNot { it in GREASE }
        val extensions = info.extensions.filterNot { it in GREASE }
        val curves = info.ellipticCurves.filterNot { it in GREASE }
        val points = info.ecPointFormats

        val ja3 = listOf(
            info.handshakeVersion.toString(),
            ciphers.joinToString("-"),
            extensions.joinToString("-"),
            curves.joinToString("-"),
            points.joinToString("-")
        ).joinToString(",")

        val ja3n = listOf(
            info.handshakeVersion.toString(),
            ciphers.joinToString("-"),
            extensions.sorted().joinToString("-"),
            curves.joinToString("-"),
            points.joinToString("-")
        ).joinToString(",")

        val topVersion = (info.supportedVersions.filterNot { it in GREASE }.maxOrNull() ?: info.handshakeVersion)
        val alpnTop = info.alpn.firstOrNull()
        val hydraLite = listOf(
            "t${versionLabel(topVersion)}",
            "c${ciphers.size}",
            "e${extensions.size}",
            alpnTop ?: "00",
            ciphers.sorted().joinToString("-"),
            extensions.sorted().joinToString("-")
        ).joinToString("_")

        return Result(
            ja3 = ja3,
            ja3Hash = md5(ja3),
            ja3n = ja3n,
            ja3nHash = md5(ja3n),
            hydraLite = hydraLite,
            hydraLiteHash = md5(hydraLite),
            sni = info.sni,
            alpn = alpnTop
        )
    }

    private fun versionLabel(v: Int): String = when (v) {
        0x0304 -> "13"
        0x0303 -> "12"
        0x0302 -> "11"
        0x0301 -> "10"
        else -> "00"
    }

    private fun md5(input: String): String {
        val digest = MessageDigest.getInstance("MD5").digest(input.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(32)
        for (b in digest) sb.append(String.format("%02x", b))
        return sb.toString()
    }
}
