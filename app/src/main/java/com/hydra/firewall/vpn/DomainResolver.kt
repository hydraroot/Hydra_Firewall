package com.hydra.firewall.vpn

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

object DomainResolver {
    private val cache = ConcurrentHashMap<String, String>()

    fun cached(ip: String): String? = cache[ip]

    fun resolve(ip: String): String? {
        val clean = ip.trim().trim('[', ']')
        if (clean.isEmpty()) return null
        cache[clean]?.let { return it }
        return runCatching {
            val host = InetAddress.getByName(clean).canonicalHostName
            if (host.isNullOrBlank() || host.equals(clean, ignoreCase = true)) null
            else host
        }.getOrNull()?.also { cache[clean] = it }
    }
}
