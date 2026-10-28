package com.hydra.firewall.vpn

import android.os.SystemClock
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Short-lived connection attribution memory used when Android 7's /proc/net
 * lookup misses a newly-created flow for a few milliseconds.
 *
 * Two safe signals are kept:
 *  - local-endpoint affinity: the same app/source port is reused for related
 *    traffic (very common for DNS/UDP and persistent TCP flows);
 *  - DNS-IP affinity is kept separately by DnsIpCorrelationStore and can be
 *    used only when candidate attribution is unique among explicitly allowed
 *    apps.
 *
 * This class never invents a UID. It only remembers a UID that was previously
 * resolved successfully.
 */
class ConnectionAffinityStore {
    data class LocalKey(
        val protocol: Int,
        val sourceAddress: String,
        val sourcePort: Int
    )

    data class Entry(
        val uid: Int,
        val packageName: String?,
        var lastSeenElapsedMs: Long,
        val firstResolvedVia: String
    )

    companion object {
        private const val TCP_TTL_MS = 30_000L
        private const val UDP_TTL_MS = 15_000L
        private const val MAX_ENTRIES = 4096
    }

    private val localMap = ConcurrentHashMap<LocalKey, Entry>()

    fun remember(protocol: Int, source: InetAddress, sourcePort: Int, uid: Int, packageName: String?, now: Long = SystemClock.elapsedRealtime()) {
        if (uid < 0 || sourcePort <= 0) return
        val key = LocalKey(protocol, canonical(source), sourcePort)
        localMap.compute(key) { _, previous ->
            if (previous == null || previous.uid != uid) {
                Entry(uid, packageName, now, "resolved")
            } else {
                previous.lastSeenElapsedMs = now
                previous
            }
        }
        if (localMap.size > MAX_ENTRIES) purge(now)
    }

    fun lookup(protocol: Int, source: InetAddress, sourcePort: Int, now: Long = SystemClock.elapsedRealtime()): Entry? {
        val key = LocalKey(protocol, canonical(source), sourcePort)
        val entry = localMap[key] ?: return null
        if (isExpired(protocol, now - entry.lastSeenElapsedMs)) {
            localMap.remove(key, entry)
            return null
        }
        entry.lastSeenElapsedMs = now
        return entry
    }

    fun clear() = localMap.clear()

    fun purge(now: Long = SystemClock.elapsedRealtime()) {
        for ((key, entry) in localMap.entries) {
            if (isExpired(key.protocol, now - entry.lastSeenElapsedMs)) {
                localMap.remove(key, entry)
            }
        }
        if (localMap.size <= MAX_ENTRIES) return
        val victims = localMap.entries
            .sortedBy { it.value.lastSeenElapsedMs }
            .take((localMap.size - MAX_ENTRIES).coerceAtLeast(1))
        victims.forEach { localMap.remove(it.key, it.value) }
    }

    fun size(): Int = localMap.size

    private fun isExpired(protocol: Int, ageMs: Long): Boolean {
        val ttl = if (protocol == UidResolver.PROTOCOL_TCP) TCP_TTL_MS else UDP_TTL_MS
        return ageMs < 0L || ageMs > ttl
    }

    private fun canonical(address: InetAddress): String = address.hostAddress?.substringBefore('%') ?: address.toString()
}
