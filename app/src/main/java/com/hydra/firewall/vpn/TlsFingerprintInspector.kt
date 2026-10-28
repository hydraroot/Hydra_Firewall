package com.hydra.firewall.vpn

import java.io.ByteArrayOutputStream

/**
 * Buffers the first bytes an app sends on a new TCP session and, if they
 * form a TLS ClientHello, computes its JA3/JA3N/Hydra-lite fingerprint.
 *
 * Designed to be called from the hot path (TcpForwardingEngine) with only
 * a per-session accumulator and a hard byte cap, so a non-TLS session (or
 * one that never completes a ClientHello within the cap) gives up cheaply
 * instead of buffering forever.
 */
object TlsFingerprintInspector {
    private const val MAX_BUFFER = 8 * 1024

    class Accumulator {
        val buffer = ByteArrayOutputStream(512)
        var gaveUp = false
        var done = false
    }

    /**
     * Feeds [data] for [session] into its accumulator. Returns a fingerprint
     * result the first (and only the first) time a full ClientHello is
     * recognized for this session; returns null on every other call
     * (still buffering, not TLS, or already finished).
     */
    fun feed(accumulator: Accumulator, data: ByteArray): Ja3Fingerprint.Result? {
        if (accumulator.done || accumulator.gaveUp) return null

        if (accumulator.buffer.size() == 0 && !TlsClientHello.looksLikeTlsRecord(data)) {
            accumulator.gaveUp = true
            return null
        }

        accumulator.buffer.write(data)
        val bytes = accumulator.buffer.toByteArray()

        val info = TlsClientHello.tryParse(bytes)
        if (info != null) {
            accumulator.done = true
            return Ja3Fingerprint.from(info)
        }

        if (bytes.size >= MAX_BUFFER) {
            accumulator.gaveUp = true
        }
        return null
    }
}
