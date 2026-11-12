package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Narrow, local-only exceptions created from a connection detail.
 *
 * Domain rules are tied to one UID. Endpoint rules are tied to one UID + IP +
 * protocol + port. A one-shot endpoint rule is consumed by the first new flow
 * to that endpoint and remains valid only for that exact flow until it closes.
 * System UIDs may only receive expiring or one-shot exceptions; permanent app
 * exceptions require a unique package identity. Threat signatures and Block All
 * are evaluated before these exceptions.
 */
object ConnectionExceptionStore {
    private const val PREFS = "hydra_connection_exceptions"
    private const val KEY = "entries"
    private const val MAX_ENTRIES = 256
    private const val FIRST_APPLICATION_UID = 10_000
    private const val ONE_SHOT_PENDING_TTL_MS = 10L * 60_000L
    private const val ONE_SHOT_CLAIM_TTL_MS = 30_000L

    @Volatile private var loaded = false
    @Volatile private var cachedEntries: List<Entry> = emptyList()
    private val packageIdentityCache = ConcurrentHashMap<String, Boolean>()
    // Active grants are in-memory only. They disappear with the VPN process and
    // are removed when the corresponding TCP/UDP session is closed.
    private data class ActiveOneShotGrant(val packageName: String, val expiresAt: Long)
    private val activeOneShotFlows = ConcurrentHashMap<String, ActiveOneShotGrant>()

    enum class Kind { DOMAIN, ENDPOINT }

    data class Entry(
        val uid: Int,
        val kind: Kind,
        val domain: String? = null,
        val ip: String? = null,
        val protocol: String? = null,
        val port: Int? = null,
        /** Package identity prevents a recycled/shared UID from inheriting another app's exception. */
        val packageName: String? = null,
        /** 0 = permanent. System UID entries are never permanent. */
        val expiresAt: Long = 0L,
        /** Pending one-shot endpoint grant; consumed by one new 5-tuple only. */
        val oneShot: Boolean = false
    ) {
        fun isExpired(now: Long): Boolean = expiresAt > 0L && expiresAt <= now
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    internal fun encode(entries: List<Entry>): String = JSONArray().also { array ->
        entries.forEach { entry ->
            array.put(JSONObject().apply {
                put("uid", entry.uid)
                put("kind", entry.kind.name)
                entry.domain?.let { put("domain", it) }
                entry.ip?.let { put("ip", it) }
                entry.protocol?.let { put("protocol", it) }
                entry.port?.let { put("port", it) }
                entry.packageName?.let { put("package", it) }
                put("expires", entry.expiresAt)
                if (entry.oneShot) put("once", true)
            })
        }
    }.toString()

    internal fun decode(raw: String): List<Entry> = runCatching {
        val array = JSONArray(raw)
        val decoded = ArrayList<Entry>()
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val uid = obj.optInt("uid", -1)
            if (uid < 0) continue
            val kind = runCatching { Kind.valueOf(obj.optString("kind")) }.getOrNull() ?: continue
            val expiresAt = obj.optLong("expires", 0L)
            if (expiresAt < 0L) continue
            val oneShot = obj.optBoolean("once", false)
            if (oneShot && (kind != Kind.ENDPOINT || expiresAt == 0L)) continue
            val storedPackageName = obj.optString("package").takeIf { it.isNotBlank() && it != "null" }
                ?.takeIf { it.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) }
            // System/shared UIDs are intentionally UID-scoped and never carry an app identity.
            val packageName = if (uid >= FIRST_APPLICATION_UID) storedPackageName else null
            if (uid >= FIRST_APPLICATION_UID && packageName == null) continue
            val entry = when (kind) {
                Kind.DOMAIN -> {
                    val domain = CustomDomainRuleStore.normalize(obj.optString("domain")) ?: continue
                    Entry(uid, kind, domain = domain, packageName = packageName, expiresAt = expiresAt)
                }
                Kind.ENDPOINT -> {
                    val ip = normalizeIp(obj.optString("ip")) ?: continue
                    val protocol = obj.optString("protocol").uppercase(Locale.US)
                    val port = obj.optInt("port", -1)
                    if (protocol !in setOf("TCP", "UDP") || port !in 1..65535) continue
                    Entry(uid, kind, ip = ip, protocol = protocol, port = port, packageName = packageName, expiresAt = expiresAt, oneShot = oneShot)
                }
            }
            if (entry.uid < FIRST_APPLICATION_UID && entry.expiresAt == 0L) continue
            decoded += entry
        }
        decoded.distinctBy(::key).takeLast(MAX_ENTRIES)
    }.getOrDefault(emptyList())

    internal fun canPersistPermanentForUid(uid: Int): Boolean = uid >= FIRST_APPLICATION_UID

    internal fun matchesScope(entry: Entry, uid: Int, packageName: String?): Boolean {
        if (entry.uid != uid) return false
        val expectedPackage = if (uid >= FIRST_APPLICATION_UID) {
            packageName?.takeIf(::isValidPackageName) ?: return false
        } else null
        return entry.packageName == expectedPackage
    }

    @Synchronized
    fun snapshot(context: Context, now: Long = System.currentTimeMillis()): List<Entry> {
        val active = activeEntries(context, now)
        return active.sortedWith(compareBy<Entry> { it.uid }.thenBy { it.kind.name }.thenBy { it.domain ?: it.ip.orEmpty() })
    }

    @Synchronized
    fun allowDomain(
        context: Context,
        uid: Int,
        domain: String,
        packageName: String? = null,
        minutes: Int? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0) return false
        val normalized = CustomDomainRuleStore.normalize(domain) ?: return false
        if (uid < FIRST_APPLICATION_UID && minutes == null) return false
        val scopedPackage = if (uid >= FIRST_APPLICATION_UID) {
            packageName?.takeIf(::isValidPackageName)?.takeIf { isUniquePackageIdentity(context, uid, it) } ?: return false
        } else null
        val expiry = minutes?.coerceIn(1, 15)?.let { now + it * 60_000L } ?: 0L
        upsert(context, Entry(uid, Kind.DOMAIN, domain = normalized, packageName = scopedPackage, expiresAt = expiry))
        return true
    }

    @Synchronized
    fun allowEndpoint(
        context: Context,
        uid: Int,
        ip: String,
        protocol: String,
        port: Int,
        packageName: String? = null,
        minutes: Int? = 5,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0 || port !in 1..65535) return false
        val normalizedIp = normalizeIp(ip) ?: return false
        val proto = protocol.uppercase(Locale.US)
        if (proto !in setOf("TCP", "UDP")) return false
        if (uid < FIRST_APPLICATION_UID && minutes == null) return false
        val scopedPackage = if (uid >= FIRST_APPLICATION_UID) {
            packageName?.takeIf(::isValidPackageName)?.takeIf { isUniquePackageIdentity(context, uid, it) } ?: return false
        } else null
        val expiry = minutes?.coerceIn(1, 15)?.let { now + it * 60_000L } ?: 0L
        upsert(context, Entry(uid, Kind.ENDPOINT, ip = normalizedIp, protocol = proto, port = port, packageName = scopedPackage, expiresAt = expiry))
        return true
    }

    /** A pending grant expires after 10 minutes if unused and is consumed by one new flow. */
    @Synchronized
    fun allowEndpointOnce(
        context: Context,
        uid: Int,
        ip: String,
        protocol: String,
        port: Int,
        packageName: String? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0 || port !in 1..65535) return false
        val normalizedIp = normalizeIp(ip) ?: return false
        val proto = protocol.uppercase(Locale.US)
        if (proto !in setOf("TCP", "UDP")) return false
        val scopedPackage = if (uid >= FIRST_APPLICATION_UID) {
            packageName?.takeIf(::isValidPackageName)?.takeIf { isUniquePackageIdentity(context, uid, it) } ?: return false
        } else null
        upsert(
            context,
            Entry(
                uid = uid,
                kind = Kind.ENDPOINT,
                ip = normalizedIp,
                protocol = proto,
                port = port,
                packageName = scopedPackage,
                expiresAt = now + ONE_SHOT_PENDING_TTL_MS,
                oneShot = true
            )
        )
        return true
    }

    fun isDomainAllowed(
        context: Context,
        uid: Int,
        domain: String,
        packageName: String? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0) return false
        val normalized = CustomDomainRuleStore.normalize(domain) ?: return false
        val entry = activeEntries(context, now).firstOrNull {
            matchesScope(it, uid, packageName) && it.kind == Kind.DOMAIN && it.domain == normalized
        } ?: return false
        return uid < FIRST_APPLICATION_UID || (isUniquePackageIdentity(context, uid, packageName) && !entry.oneShot)
    }

    /**
     * Persistent/temporary exceptions match without filesystem sorting or Binder work
     * unless an exact candidate exists. One-shot entries are atomically consumed and
     * attached to the concrete SessionKey flow ID so policy refreshes keep that flow
     * alive but a second connection cannot reuse the grant.
     */
    fun isEndpointAllowed(
        context: Context,
        uid: Int,
        ip: String,
        protocol: String,
        port: Int,
        packageName: String? = null,
        flowId: String? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0 || port !in 1..65535) return false
        val normalizedIp = normalizeIp(ip) ?: return false
        val proto = protocol.uppercase(Locale.US)
        if (proto !in setOf("TCP", "UDP")) return false

        val activeFlowId = flowId?.takeIf { it.isNotBlank() }
        val scopedPackageName = if (uid >= FIRST_APPLICATION_UID) packageName else null
        if (activeFlowId != null) {
            val activeGrant = activeOneShotFlows[activeFlowId]
            if (activeGrant != null && activeGrant.packageName == scopedPackageName.orEmpty() && activeGrant.expiresAt > now) return true
            if (activeGrant != null) activeOneShotFlows.remove(activeFlowId, activeGrant)
        }

        // The fast path is a simple in-memory scan (maximum 256 rules). If there is
        // no matching exception, do not call PackageManager and do not sort the list.
        val candidate = activeEntries(context, now).firstOrNull {
            matchesScope(it, uid, packageName) && it.kind == Kind.ENDPOINT && it.ip == normalizedIp &&
                it.protocol == proto && it.port == port
        } ?: return false

        if (uid >= FIRST_APPLICATION_UID && !isUniquePackageIdentity(context, uid, packageName)) return false
        if (!candidate.oneShot) return true
        if (activeFlowId == null) return false

        synchronized(this) {
            val activeGrant = activeOneShotFlows[activeFlowId]
            if (activeGrant != null && activeGrant.packageName == scopedPackageName.orEmpty() && activeGrant.expiresAt > now) return true
            if (activeGrant != null) activeOneShotFlows.remove(activeFlowId, activeGrant)
            val latest = activeEntries(context, now).firstOrNull {
                matchesScope(it, uid, packageName) && it.kind == Kind.ENDPOINT && it.ip == normalizedIp &&
                    it.protocol == proto && it.port == port
            } ?: return false
            if (!latest.oneShot) return true
            save(context, load(context).filterNot { key(it) == key(latest) })
            activeOneShotFlows[activeFlowId] = ActiveOneShotGrant(
                packageName = scopedPackageName.orEmpty(),
                expiresAt = now + ONE_SHOT_CLAIM_TTL_MS
            )
            return true
        }
    }

    /** Called after the forwarding engine has successfully published the session. */
    fun confirmOneShotFlow(flowId: String) {
        if (flowId.isBlank()) return
        activeOneShotFlows.computeIfPresent(flowId) { _, grant -> grant.copy(expiresAt = Long.MAX_VALUE) }
    }

    fun releaseOneShotFlow(flowId: String) {
        if (flowId.isNotBlank()) activeOneShotFlows.remove(flowId)
    }

    /** A restarted VPN has no surviving sockets, so no in-memory one-shot flow can remain valid. */
    fun clearActiveOneShotFlows() {
        activeOneShotFlows.clear()
    }

    @Synchronized
    fun remove(context: Context, entry: Entry) {
        save(context, load(context).filterNot { key(it) == key(entry) })
    }

    @Synchronized
    fun clear(context: Context) {
        save(context, emptyList())
        activeOneShotFlows.clear()
    }

    /** Call on package add/replace/remove broadcasts to prevent stale shared-UID ownership. */
    fun invalidatePackageIdentityCache() {
        packageIdentityCache.clear()
        // A package replacement can change UID ownership. Do not let an already
        // consumed one-shot grant survive that identity transition.
        activeOneShotFlows.clear()
    }

    private fun load(context: Context): List<Entry> {
        if (loaded) return cachedEntries
        synchronized(this) {
            if (!loaded) {
                cachedEntries = decode(prefs(context).getString(KEY, "[]").orEmpty())
                loaded = true
            }
            return cachedEntries
        }
    }

    private fun activeEntries(context: Context, now: Long): List<Entry> {
        val all = load(context)
        val active = all.filterNot { it.isExpired(now) }
        if (active.size != all.size) {
            synchronized(this) {
                val latest = load(context)
                val stillActive = latest.filterNot { it.isExpired(now) }
                if (stillActive.size != latest.size) save(context, stillActive)
            }
        }
        return active
    }

    private fun save(context: Context, entries: List<Entry>) {
        val safe = entries.takeLast(MAX_ENTRIES)
        prefs(context).edit().putString(KEY, encode(safe)).apply()
        cachedEntries = safe
        loaded = true
    }

    private fun upsert(context: Context, entry: Entry) {
        val updated = load(context).filterNot { key(it) == key(entry) } + entry
        save(context, updated)
    }

    private fun key(entry: Entry): String = when (entry.kind) {
        Kind.DOMAIN -> "${entry.uid}|${entry.packageName.orEmpty()}|D|${entry.domain}"
        Kind.ENDPOINT -> "${entry.uid}|${entry.packageName.orEmpty()}|E|${entry.ip}|${entry.protocol}|${entry.port}"
    }

    /** Cache is invalidated by AppLifecycleWatcher, so packet processing avoids Binder calls. */
    private fun isUniquePackageIdentity(context: Context, uid: Int, packageName: String?): Boolean {
        if (uid < FIRST_APPLICATION_UID || packageName == null || !isValidPackageName(packageName)) return false
        val cacheKey = "$uid|$packageName"
        packageIdentityCache[cacheKey]?.let { return it }
        val packages = runCatching {
            context.applicationContext.packageManager.getPackagesForUid(uid)
                ?.filter { it.isNotBlank() }
                ?.distinct()
                .orEmpty()
        }.getOrDefault(emptyList())
        val valid = packages.size == 1 && packages.single() == packageName
        if (packageIdentityCache.size >= 1024) packageIdentityCache.clear()
        packageIdentityCache.putIfAbsent(cacheKey, valid)
        return valid
    }

    private fun isValidPackageName(value: String): Boolean =
        value.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))

    private fun normalizeIp(value: String): String? {
        val raw = value.trim().substringBefore('%')
        if (raw.isBlank() || raw.contains('/') || raw.contains(' ')) return null
        if (!raw.matches(Regex("[0-9A-Fa-f:.]{2,45}"))) return null
        return runCatching { InetAddress.getByName(raw).hostAddress?.substringBefore('%') }.getOrNull()
    }
}
