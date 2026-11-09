package com.hydra.firewall.vpn

import java.io.ByteArrayOutputStream

/**
 * Buffers the first bytes an app sends on a new TCP session and, if they
 * form a TLS ClientHello, extracts its SNI. The SNI drives the domain
 * blocklist / threat-intel enforcement on TCP (IPv4 and IPv6).
 *
 * Designed to be called from the hot path (TcpForwardingEngine) with only
 * a per-session accumulator and a hard byte cap, so a non-TLS session (or
 * one that never completes a ClientHello within the cap) gives up cheaply
 * instead of buffering forever.
 */
object TlsSniInspector {
    /**
     * Un registro TLS lleva como máximo 16 384 bytes (+5 de cabecera). Con 8 KB, una app podía rellenar el
     * ClientHello (extensión padding) para pasar el tope y que no se leyera el SNI; con este valor se cubre
     * cualquier ClientHello que viaje en un solo registro.
     */
    private const val MAX_BUFFER = 16 * 1024 + 5

    class Accumulator {
        val buffer = ByteArrayOutputStream(512)
        var gaveUp = false
        var done = false
    }

    /** Resultado de un ClientHello completo; [sni] es null si el cliente no lo envía. */
    class Result(val sni: String?)

    /**
     * Feeds [data] for a session into its accumulator. Returns a [Result]
     * the first (and only the first) time a full ClientHello is recognized
     * for this session; returns null on every other call (still buffering,
     * not TLS, or already finished).
     */
    fun feed(accumulator: Accumulator, data: ByteArray): Result? {
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
            return Result(info.sni)
        }

        if (bytes.size >= MAX_BUFFER) {
            accumulator.gaveUp = true
        }
        return null
    }
}
