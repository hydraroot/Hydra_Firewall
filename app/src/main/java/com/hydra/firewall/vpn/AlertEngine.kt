package com.hydra.firewall.vpn

import android.content.Context
import com.hydra.firewall.security.ThreatSignatureStore
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Decide cuándo vale la pena preguntarle al usuario "¿bloqueamos esto?". Se llama desde [ConnectionHistory.add] por cada
 * conexión permitida y trabaja en un hilo aparte para no frenar el tráfico. Reglas deliberadamente conservadoras:
 *  - THREAT: el destino (dominio o IP) está en las listas de amenazas.
 *  - NEW_DESTINATION: una app de usuario que ya tiene un historial de destinos (>= [BASELINE]) se conecta a un dominio nuevo.
 * Límite: 1 aviso por app cada 10 min y 6 por hora en total.
 */
object AlertEngine {
    private const val BASELINE = 30
    private const val PER_APP_COOLDOWN_MS = 10 * 60_000L
    private const val GLOBAL_WINDOW_MS = 60 * 60_000L
    private const val GLOBAL_MAX = 6
    private const val SEEN_CAP = 300

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "hydra-alerts").apply { isDaemon = true } }
    private val seen = ConcurrentHashMap<Int, MutableSet<String>>()
    private val lastAlertByUid = ConcurrentHashMap<Int, Long>()
    private val globalTimes = ArrayDeque<Long>()
    @Volatile private var appContext: Context? = null

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    fun onAllowedConnection(uid: Int, pkg: String?, destination: String, event: String) {
        if (event != "OPEN" && event != "FIRST-SEEN") return
        val ctx = appContext ?: return
        executor.execute { runCatching { evaluate(ctx, uid, pkg, destination) } }
    }

    private fun evaluate(ctx: Context, uid: Int, pkg: String?, destination: String) {
        if (uid < 10000) return // el sistema Android no se avisa: se gestiona desde Reglas
        val ip = parseHost(destination) ?: return
        val addr = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return
        if (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress || addr.isAnyLocalAddress) return
        if (IpBlockStore(ctx).isBlocked(ip)) return
        val domain = DnsIpCorrelationStore.lookup(uid, addr)
        val host = domain ?: ip

        val threat = (domain?.let { ThreatSignatureStore.matchDomain(ctx, it) } ?: ThreatSignatureStore.matchIp(ctx, ip)) != null
        val reason: AlertStore.Reason
        if (threat) {
            reason = AlertStore.Reason.THREAT
        } else {
            if (domain == null) return // sin dominio solo serían IPs de CDN: demasiado ruido
            val set = seen.getOrPut(uid) { java.util.Collections.synchronizedSet(LinkedHashSet<String>()) }
            val isNew = set.add(registrable(domain))
            if (set.size > SEEN_CAP) synchronized(set) { set.iterator().let { it.next(); it.remove() } }
            if (!isNew || set.size < BASELINE) return
            reason = AlertStore.Reason.NEW_DESTINATION
        }

        if (AlertStore.isIgnored(ctx, uid, ip)) return
        val now = System.currentTimeMillis()
        if (reason != AlertStore.Reason.THREAT) {
            if (now - (lastAlertByUid[uid] ?: 0L) < PER_APP_COOLDOWN_MS) return
            synchronized(globalTimes) {
                while (globalTimes.isNotEmpty() && now - globalTimes.first() > GLOBAL_WINDOW_MS) globalTimes.removeFirst()
                if (globalTimes.size >= GLOBAL_MAX) return
            }
        }
        val label = AppNames.label(uid, pkg)
        val alert = AlertStore.create(ctx, uid, pkg, label, host, ip, reason) ?: return
        lastAlertByUid[uid] = now
        synchronized(globalTimes) { globalTimes.addLast(now) }
        NotificationHelper.notifyBlockAlert(ctx, alert)
    }

    /** "1.2.3.4:443" o "[2001:db8::1]:443" -> la IP sin puerto. */
    internal fun parseHost(destination: String): String? {
        val d = destination.trim()
        if (d.isEmpty()) return null
        return if (d.startsWith("[")) d.substringAfter('[').substringBefore(']').ifBlank { null }
        else d.substringBeforeLast(':', d).ifBlank { null }
    }

    /** Dominio "base" aproximado (últimas dos etiquetas) para no contar cada subdominio como destino nuevo. */
    internal fun registrable(domain: String): String {
        val parts = domain.trim('.').lowercase().split('.')
        return if (parts.size <= 2) parts.joinToString(".") else parts.takeLast(2).joinToString(".")
    }
}
