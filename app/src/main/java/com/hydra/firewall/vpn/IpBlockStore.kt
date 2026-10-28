package com.hydra.firewall.vpn

import android.content.Context
import java.math.BigInteger
import java.net.InetAddress

class IpBlockStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("firewall_ips", Context.MODE_PRIVATE)

    fun getBlocked(): List<String> = prefs.getStringSet(KEY, emptySet())!!.toList().sorted()

    fun isBlocked(host: String): Boolean {
        val target = parseAddress(host) ?: return false
        return prefs.getStringSet(KEY, emptySet()).orEmpty().any { matchesRule(target, it) }
    }

    fun add(host: String) {
        val normalized = normalize(host) ?: return
        val current = prefs.getStringSet(KEY, emptySet()).orEmpty().toMutableSet()
        current.add(normalized)
        prefs.edit().putStringSet(KEY, current).commit()
    }

    fun remove(host: String) {
        val normalized = normalize(host) ?: host.trim()
        val current = prefs.getStringSet(KEY, emptySet()).orEmpty().toMutableSet()
        current.remove(host)
        current.remove(normalized)
        prefs.edit().putStringSet(KEY, current).commit()
    }

    /** Explicit per-UID exception for one destination IP. This does not remove
     * the global IP block; it is a narrower user rule used to permit a specific
     * app/UID to reach one IP after Hydra blocked it for another policy reason. */
    fun isAllowedForUid(uid: Int, host: String): Boolean {
        val normalized = normalize(host) ?: return false
        return prefs.getStringSet(KEY_ALLOWED_UID_IPS, emptySet()).orEmpty().contains("$uid|$normalized")
    }

    fun allowForUid(uid: Int, host: String) {
        val normalized = normalize(host) ?: return
        val current = prefs.getStringSet(KEY_ALLOWED_UID_IPS, emptySet()).orEmpty().toMutableSet()
        current.add("$uid|$normalized")
        prefs.edit().putStringSet(KEY_ALLOWED_UID_IPS, current).commit()
    }

    fun removeAllowedForUid(uid: Int, host: String) {
        val normalized = normalize(host) ?: host.trim()
        val current = prefs.getStringSet(KEY_ALLOWED_UID_IPS, emptySet()).orEmpty().toMutableSet()
        current.remove("$uid|$normalized")
        prefs.edit().putStringSet(KEY_ALLOWED_UID_IPS, current).commit()
    }

    fun clear() = prefs.edit().remove(KEY).remove(KEY_ALLOWED_UID_IPS).commit()

    private fun normalize(value: String): String? {
        val v = value.trim()
        if (v.isEmpty()) return null
        if (v.contains('-') && !v.contains(':')) {
            val parts = v.split('-', limit = 2).map { it.trim() }
            val a = parseAddress(parts[0]) ?: return null
            val b = parseAddress(parts[1]) ?: return null
            if (a.address.size == 4 && b.address.size == 4 && toBigInt(a) <= toBigInt(b)) return "${parts[0]}-${parts[1]}"
            return null
        }
        if (v.contains('/')) {
            val parts = v.split('/', limit = 2)
            val addr = parseAddress(parts[0]) ?: return null
            val prefix = parts[1].toIntOrNull() ?: return null
            val max = addr.address.size * 8
            if (prefix !in 0..max) return null
            return "${addr.hostAddress}/$prefix"
        }
        return parseAddress(v)?.hostAddress
    }

    private fun matchesRule(target: InetAddress, rule: String): Boolean {
        val r = rule.trim()
        if (r.contains('-') && !r.contains('/')) {
            val parts = r.split('-', limit = 2)
            val a = parseAddress(parts[0]) ?: return false
            val b = parseAddress(parts[1]) ?: return false
            return a.address.size == target.address.size && toBigInt(target) in toBigInt(a)..toBigInt(b)
        }
        if (r.contains('/')) {
            val parts = r.split('/', limit = 2)
            val network = parseAddress(parts[0]) ?: return false
            val prefix = parts[1].toIntOrNull() ?: return false
            if (network.address.size != target.address.size || prefix !in 0..network.address.size * 8) return false
            val mask = if (prefix == 0) BigInteger.ZERO else BigInteger.ONE.shiftLeft(network.address.size * 8).subtract(BigInteger.ONE).shiftRight(network.address.size * 8 - prefix).shiftLeft(network.address.size * 8 - prefix)
            return toBigInt(network).and(mask) == toBigInt(target).and(mask)
        }
        val exact = parseAddress(r) ?: return false
        return exact.address.contentEquals(target.address)
    }

    private fun parseAddress(host: String): InetAddress? = runCatching { InetAddress.getByName(host.trim()) }.getOrNull()

    private fun toBigInt(addr: InetAddress): BigInteger = BigInteger(1, addr.address)

    companion object {
        private const val KEY = "blocked_ips"
        private const val KEY_ALLOWED_UID_IPS = "allowed_uid_ips"
    }
}
