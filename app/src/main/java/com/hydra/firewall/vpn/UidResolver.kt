package com.hydra.firewall.vpn

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * V1.1 - Pieza central de esta versión.
 *
 * la tupla del paquete tal cual sale de la TUN (incluyendo la IP virtual
 * de origen) se pasa SIN transformación a getConnectionOwnerUid(). No hay
 * traducción ni resolución DNS intermedia. Replicamos exactamente ese patrón.
 *
 * Regla no negociable (condición de la auditoría): si la resolución falla,
 * NUNCA se sustituye por un valor inventado o aproximado. Se reporta
 * Process.INVALID_UID explícitamente.
 */
class UidResolver(context: Context) {

    companion object {
        private const val TAG = "UidResolver"
        const val UID_CACHE_TTL_MS = 30_000L
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17
    }

    private val appContext = context.applicationContext
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager: PackageManager = appContext.packageManager

    data class CacheEntry(val uid: Int, val timestampMs: Long, val resolvedVia: String)

    private val uidCache = ConcurrentHashMap<SessionKey, CacheEntry>()
    private val packageNameCache = ConcurrentHashMap<Int, String>()
    private val affinityStore = ConnectionAffinityStore()
    private val ruleStore = RuleStore(appContext)

    data class Resolution(
        val uid: Int,
        val packageName: String?,
        val fromCache: Boolean,
        val resolvedVia: String,
        val fromAffinity: Boolean = false
    )

    /**
     * Resuelve el UID para la 5-tupla exacta que llegó del paquete TUN.
     * No se debe llamar para cada paquete de una sesión ya vista: el caller
     * (FirewallVpnService) decide cuándo corresponde (SYN nuevo para TCP,
     *
     * Despacho por versión de API, replicando la misma rama que verificamos
     *   API 29+   -> ConnectivityManager.getConnectionOwnerUid()
     *   API 24-28 -> fallback histórico vía /proc/net/{tcp,tcp6,udp,udp6}
     */
    fun resolve(key: SessionKey): Resolution = resolve(key, NetworkKind.NONE)

    /**
     * Resolves a flow and, on an attribution miss, may reuse a short-lived
     * source-endpoint identity that was previously resolved successfully.
     *
     * Affinity is intentionally restricted to UIDs that have an explicit
     * allow rule for the active network (or a temporary allow). This prevents
     * the recovery mechanism from turning an arbitrary unresolved flow into an
     * open firewall path.
     */
    fun resolve(key: SessionKey, network: NetworkKind): Resolution {
        val now = System.currentTimeMillis()
        val elapsedNow = SystemClock.elapsedRealtime()

        val cached = uidCache[key]
        if (cached != null && (now - cached.timestampMs) < UID_CACHE_TTL_MS) {
            val pkg = packageNameFor(cached.uid)
            affinityStore.remember(key.protocol, key.srcAddr, key.srcPort, cached.uid, pkg, elapsedNow)
            return Resolution(cached.uid, pkg, fromCache = true, resolvedVia = cached.resolvedVia)
        }

        val (uid, via) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            queryConnectionOwnerUid(key) to "getConnectionOwnerUid"
        } else {
            resolveLegacyWithRetry(key)
        }

        // A transient /proc miss is common during the first milliseconds of a
        // connection on older Android versions. Never cache that failure for the
        // full TTL: doing so can make a permitted app appear permanently offline
        // until the cache expires. Successful resolutions are still cached.
        if (uid != Process.INVALID_UID) {
            val pkg = packageNameFor(uid)
            uidCache[key] = CacheEntry(uid, now, via)
            affinityStore.remember(key.protocol, key.srcAddr, key.srcPort, uid, pkg, elapsedNow)
            return Resolution(uid, pkg, fromCache = false, resolvedVia = via)
        }

        uidCache.remove(key)

        // First recovery path: same local endpoint (protocol + source IP +
        // source port) was resolved to an explicitly allowed app moments ago.
        val localAffinity = affinityStore.lookup(key.protocol, key.srcAddr, key.srcPort, elapsedNow)
        if (localAffinity != null && isAffinityAllowed(localAffinity.uid, network)) {
            Log.i(TAG, "UID affinity hit uid=${localAffinity.uid} pkg=${localAffinity.packageName ?: "unknown"} src=${key.srcAddr.hostAddress}:${key.srcPort} via=local-endpoint")
            DiagnosticLogger.logServiceEvent(
                "UID_AFFINITY_HIT uid=${localAffinity.uid} pkg=${localAffinity.packageName ?: "unknown"} src=${key.srcAddr.hostAddress}:${key.srcPort} via=local-endpoint"
            )
            return Resolution(
                localAffinity.uid,
                localAffinity.packageName ?: packageNameFor(localAffinity.uid),
                fromCache = false,
                resolvedVia = "endpoint-affinity",
                fromAffinity = true
            )
        }

        // La IP de destino NO es prueba de identidad (CDN/IP compartida entre apps):
        // no se usa para atribuir ni autorizar tráfico. Si no hay UID, fail-closed.
        UnresolvedUidPromptRecovery.schedule(appContext, key, network, this)
        return Resolution(Process.INVALID_UID, null, fromCache = false, resolvedVia = via)
    }

    private fun isAffinityAllowed(uid: Int, network: NetworkKind): Boolean {
        if (uid == Process.INVALID_UID) return false
        val temporary = ruleStore.getTemporaryRule(uid)
        if (temporary != null) {
            return when (network) {
                NetworkKind.WIFI -> temporary.wifiAllowed
                NetworkKind.MOBILE -> temporary.mobileAllowed
                NetworkKind.OTHER -> temporary.wifiAllowed || temporary.mobileAllowed
                NetworkKind.NONE -> false
            }
        }
        if (!ruleStore.hasExplicitRule(uid)) return false
        val rule = ruleStore.getRule(uid)
        return when (network) {
            NetworkKind.WIFI -> rule.wifiAllowed
            NetworkKind.MOBILE -> rule.mobileAllowed
            NetworkKind.OTHER -> rule.wifiAllowed || rule.mobileAllowed
            NetworkKind.NONE -> false
        }
    }

    private fun resolveLegacyWithRetry(key: SessionKey): Pair<Int, String> {
        // On Android 7/8/9 the socket can appear in /proc/net a little after the
        // first TUN SYN/UDP packet is observed. A short bounded retry window is
        // preferable to immediately turning a real app into INVALID_UID -> BLOCK.
        // Espera total acotada a 85 ms (0+10+25+50) en el hilo del motor. Los reintentos largos
        // los hace UnresolvedUidPromptRecovery en segundo plano.
        val delays = longArrayOf(0L, 10L, 25L, 50L)
        for (index in delays.indices) {
            if (delays[index] > 0L) {
                try { Thread.sleep(delays[index]) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
            val resolved = ProcNetUidResolver.resolve(key)
            if (resolved != null) {
                return resolved to if (index == 0) "/proc/net" else "/proc/net retry${index}"
            }
        }
        DiagnosticLogger.logServiceEvent(
            "UID_RESOLUTION_FAILED protocol=${key.protocol} src=${key.srcAddr.hostAddress}:${key.srcPort} dst=${key.dstAddr.hostAddress}:${key.dstPort} via=/proc/net retries=${delays.size}"
        )
        return Process.INVALID_UID to "/proc/net failed"
    }

    /**
     * Llamada directa a la API oficial, replicando exactamente el patrón
     * construyendo InetSocketAddress tal cual con lo que vino del paquete.
     */
    @TargetApi(Build.VERSION_CODES.Q)
    private fun queryConnectionOwnerUid(key: SessionKey): Int {
        if (key.protocol != PROTOCOL_TCP && key.protocol != PROTOCOL_UDP) {
            return Process.INVALID_UID
        }

        val local = InetSocketAddress(key.srcAddr, key.srcPort)
        val remote = InetSocketAddress(key.dstAddr, key.dstPort)

        return try {
            connectivityManager.getConnectionOwnerUid(key.protocol, local, remote)
        } catch (e: SecurityException) {
            // No debería ocurrir siendo la app dueña de la VPN activa, pero no
            // asumimos: si pasa, se reporta como fallo real, no se inventa un UID.
            Process.INVALID_UID
        }
    }

    private fun packageNameFor(uid: Int): String? {
        if (uid == Process.INVALID_UID) return null

        packageNameCache[uid]?.let { return it }

        val packages = packageManager.getPackagesForUid(uid)
        val name = packages?.firstOrNull()
        if (name != null) {
            packageNameCache[uid] = name
        }
        return name
    }

    /** Limpieza periódica de entradas vencidas, para no crecer indefinidamente. */
    fun purgeExpired() {
        val now = System.currentTimeMillis()
        val iterator = uidCache.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.timestampMs > UID_CACHE_TTL_MS) {
                iterator.remove()
            }
        }
        affinityStore.purge()
    }

    fun clear() {
        uidCache.clear()
        packageNameCache.clear()
        affinityStore.clear()
        DnsIpCorrelationStore.clear()
    }
}

/**
 * la clave nunca puede ser solamente el puerto de origen.
 */
data class SessionKey(
    val protocol: Int,
    val srcAddr: InetAddress,
    val srcPort: Int,
    val dstAddr: InetAddress,
    val dstPort: Int
)
