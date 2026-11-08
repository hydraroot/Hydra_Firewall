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
        // F3 fix (security audit): the local-endpoint key is effectively just
        // (protocol, sourcePort) inside a VpnService tunnel, because every app
        // shares the same virtual source address (e.g. 10.0.0.2). Ephemeral
        // ports are assigned by the kernel for the whole device and are
        // routinely reused across unrelated apps within seconds. The original
        // 15-30s TTLs turned this into a cross-app attribution window, not the
        // "race during /proc/net lookup" the mechanism was meant to cover.
        // Shrinking the TTL to match that actual race (low hundreds of ms)
        // reduces the exposure window by 1-2 orders of magnitude without
        // touching the call sites. This is the minimal/low-risk mitigation;
        // the audit's recommended complete fix is to stop caching by port
        // across distinct flows entirely and instead re-query
        // getConnectionOwnerUid() per 4-tuple on every resolution miss.
        private const val TCP_TTL_MS = 800L
        private const val UDP_TTL_MS = 500L
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
