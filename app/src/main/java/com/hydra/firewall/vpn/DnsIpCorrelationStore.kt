package com.hydra.firewall.vpn

import android.os.SystemClock
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Short-lived DNS answer cache used to correlate a later UDP/443 QUIC flow with
 * a domain that the same app resolved. It does not decrypt QUIC. It only helps
 * Hydra apply an already-known domain decision when DNS resolution preceded the
 * HTTP/3 flow and the mapping is still fresh.
 */
object DnsIpCorrelationStore {
    private const val TTL_MS = 2 * 60 * 1000L
    private const val MAX_ENTRIES = 4096

    private data class Entry(val uid: Int, val domain: String, val expiresAt: Long, val threat: Boolean)
    private val map = ConcurrentHashMap<String, Entry>()
    private val reverse = ConcurrentHashMap<String, ConcurrentHashMap<Int, Long>>()

    fun recordResponse(uid: Int, message: ByteArray, threat: Boolean = false) {
        if (uid == android.os.Process.INVALID_UID) return
        val records = DnsWireParser.extractAddressAnswers(message) ?: return
        val now = SystemClock.elapsedRealtime()
        for (r in records) {
            val hostKey = hostKey(r.address)
            val expiry = now + TTL_MS
            map[key(uid, r.address)] = Entry(uid, r.domain, expiry, threat)
            reverse.computeIfAbsent(hostKey) { ConcurrentHashMap() }[uid] = expiry
        }
        if (map.size > MAX_ENTRIES) purge(now)
    }

    fun lookup(uid: Int, address: InetAddress): String? {
        val now = SystemClock.elapsedRealtime()
        val e = map[key(uid, address)] ?: return null
        if (e.expiresAt < now) {
            map.remove(key(uid, address), e)
            return null
        }
        return e.domain
    }

    fun clear() {
        map.clear()
        reverse.clear()
    }

    /**
     * Returns UIDs that recently resolved this destination IP. The caller must
     * apply its own policy before using a candidate for attribution.
     */
    fun candidateUids(address: InetAddress): List<Int> {
        val hostKey = hostKey(address)
        val bucket = reverse[hostKey] ?: return emptyList()
        val now = SystemClock.elapsedRealtime()
        val out = ArrayList<Int>(bucket.size)
        for ((uid, expiry) in bucket.entries) {
            if (expiry >= now) out += uid else bucket.remove(uid, expiry)
        }
        if (bucket.isEmpty()) reverse.remove(hostKey, bucket)
        return out
    }

    private fun purge(now: Long) {
        for ((k, v) in map.entries) {
            if (v.expiresAt < now) {
                map.remove(k, v)
            }
        }
        for ((host, bucket) in reverse.entries) {
            for ((uid, expiry) in bucket.entries) {
                if (expiry < now) bucket.remove(uid, expiry)
            }
            if (bucket.isEmpty()) reverse.remove(host, bucket)
        }
        if (map.size <= MAX_ENTRIES) return
        // Best-effort bounded eviction: remove roughly the oldest quarter.
        val victims = map.entries.sortedBy { it.value.expiresAt }.take(map.size / 4)
        victims.forEach { entry ->
            if (map.remove(entry.key, entry.value)) {
                val host = entry.key.substringAfter('|', "")
                val uid = entry.value.uid
                val bucket = reverse[host]
                bucket?.remove(uid, entry.value.expiresAt)
                if (bucket != null && bucket.isEmpty()) reverse.remove(host, bucket)
            }
        }
    }

    private fun key(uid: Int, addr: InetAddress): String = "$uid|${hostKey(addr)}"

    private fun hostKey(addr: InetAddress): String = addr.hostAddress?.substringBefore('%') ?: ""
}

/** Tiny bounded parser for A/AAAA answers in DNS responses. */
object DnsWireParser {
    data class AddressAnswer(val domain: String, val address: InetAddress)

    fun extractAddressAnswers(message: ByteArray): List<AddressAnswer>? {
        if (!DnsMessageValidator.isResponse(message) || message.size < 12) return null
        val qd = u16(message, 4)
        val an = u16(message, 6)
        var off = 12
        repeat(qd) {
            off = skipName(message, off) ?: return null
            if (off + 4 > message.size) return null
            off += 4
        }
        val out = mutableListOf<AddressAnswer>()
        repeat(an.coerceAtMost(64)) {
            val name = readName(message, off) ?: return@repeat
            off += name.bytes
            if (off + 10 > message.size) return@repeat
            val type = u16(message, off)
            val clazz = u16(message, off + 2)
            val rdLen = u16(message, off + 8)
            off += 10
            if (off + rdLen > message.size) return@repeat
            if (clazz == 1 && (type == 1 || type == 28) && (rdLen == 4 || rdLen == 16)) {
                val bytes = message.copyOfRange(off, off + rdLen)
                runCatching { out += AddressAnswer(name.value.lowercase(), InetAddress.getByAddress(bytes)) }
            }
            off += rdLen
        }
        return out
    }

    private data class Name(val value: String, val bytes: Int)

    private fun readName(data: ByteArray, start: Int): Name? {
        var off = start
        var consumed = 0
        var steps = 0
        val sb = StringBuilder()
        while (off < data.size && steps++ < 128) {
            val len = data[off].toInt() and 0xFF
            if (len == 0) return Name(sb.toString(), consumed + 1)
            if ((len and 0xC0) == 0xC0) {
                if (off + 1 >= data.size) return null
                val ptr = ((len and 0x3F) shl 8) or (data[off + 1].toInt() and 0xFF)
                val pointed = readName(data, ptr) ?: return null
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(pointed.value)
                return Name(sb.toString(), consumed + 2)
            }
            if (len > 63 || off + 1 + len > data.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            repeat(len) { i -> sb.append(data[off + 1 + i].toInt().toChar()) }
            off += 1 + len
            consumed += 1 + len
        }
        return null
    }

    private fun skipName(data: ByteArray, start: Int): Int? {
        var off = start
        var steps = 0
        while (off < data.size && steps++ < 128) {
            val len = data[off].toInt() and 0xFF
            if (len == 0) return off + 1
            if ((len and 0xC0) == 0xC0) return if (off + 1 < data.size) off + 2 else null
            if (len > 63 || off + 1 + len > data.size) return null
            off += 1 + len
        }
        return null
    }

    private fun u16(d: ByteArray, o: Int): Int =
        ((d[o].toInt() and 0xFF) shl 8) or (d[o + 1].toInt() and 0xFF)
}
