package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.Locale

/**
 * Narrow, local-only exceptions created from a connection detail.
 *
 * Domain rules are tied to one UID. Endpoint rules are tied to one UID + IP +
 * protocol + port. System UIDs (< FIRST_APPLICATION_UID) may only receive
 * expiring exceptions; permanent app-level exceptions are restricted to a
 * regular app UID. Confirmed threat matches and the global Block All switch
 * are evaluated before these exceptions by the rule engines.
 */
object ConnectionExceptionStore {
    private const val PREFS = "hydra_connection_exceptions"
    private const val KEY = "entries"
    private const val MAX_ENTRIES = 256
    private const val FIRST_APPLICATION_UID = 10_000
    @Volatile private var loaded = false
    @Volatile private var cachedEntries: List<Entry> = emptyList()

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
        val expiresAt: Long = 0L
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
            val storedPackageName = obj.optString("package").takeIf { it.isNotBlank() && it != "null" }
                ?.takeIf { it.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) }
            // System/shared UIDs are intentionally UID-scoped and never carry an app identity.
            // Normalize persisted data too, so a copied/tampered package field cannot create
            // a system exception that is impossible to match or imply an app-level guarantee.
            val packageName = if (uid >= FIRST_APPLICATION_UID) storedPackageName else null
            // Regular app exceptions without package identity are discarded: they
            // could otherwise be inherited if Android later recycles the UID.
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
                    Entry(uid, kind, ip = ip, protocol = protocol, port = port, packageName = packageName, expiresAt = expiresAt)
                }
            }
            // Never accept imported/tampered permanent rules for system UIDs.
            if (entry.uid < FIRST_APPLICATION_UID && entry.expiresAt == 0L) continue
            decoded += entry
        }
        decoded.distinctBy(::key).takeLast(MAX_ENTRIES)
    }.getOrDefault(emptyList())

    internal fun canPersistPermanentForUid(uid: Int): Boolean = uid >= FIRST_APPLICATION_UID

    /** Package identity is required for app UIDs; shared/system UIDs are deliberately UID-scoped. */
    internal fun matchesScope(entry: Entry, uid: Int, packageName: String?): Boolean {
        if (entry.uid != uid) return false
        val expectedPackage = if (uid >= FIRST_APPLICATION_UID) {
            packageName?.takeIf(::isValidPackageName) ?: return false
        } else null
        return entry.packageName == expectedPackage
    }

    @Synchronized
    fun snapshot(context: Context, now: Long = System.currentTimeMillis()): List<Entry> {
        val all = load(context)
        val active = all.filterNot { it.isExpired(now) }
        if (active.size != all.size) save(context, active)
        return active.sortedWith(compareBy<Entry> { it.uid }.thenBy { it.kind.name }.thenBy { it.domain ?: it.ip.orEmpty() })
    }

    /** Permanent for a regular app UID; temporary-only for system/shared service UIDs. */
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

    /** Exact network endpoint. System UIDs are limited to a maximum 15-minute lease. */
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

    fun isDomainAllowed(
        context: Context,
        uid: Int,
        domain: String,
        packageName: String? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (uid < 0) return false
        val normalized = CustomDomainRuleStore.normalize(domain) ?: return false
        if (uid >= FIRST_APPLICATION_UID && !isUniquePackageIdentity(context, uid, packageName)) return false
        return snapshot(context, now).any {
            matchesScope(it, uid, packageName) && it.kind == Kind.DOMAIN && it.domain == normalized
        }
    }

    fun isEndpointAllowed(
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
        if (uid >= FIRST_APPLICATION_UID && !isUniquePackageIdentity(context, uid, packageName)) return false
        return snapshot(context, now).any {
            matchesScope(it, uid, packageName) && it.kind == Kind.ENDPOINT && it.ip == normalizedIp &&
                it.protocol == proto && it.port == port
        }
    }

    @Synchronized
    fun remove(context: Context, entry: Entry) {
        save(context, load(context).filterNot { key(it) == key(entry) })
    }

    @Synchronized
    fun clear(context: Context) = save(context, emptyList())

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

    /** Reject app-scoped exceptions for shared UIDs because Android attributes traffic by UID. */
    private fun isUniquePackageIdentity(context: Context, uid: Int, packageName: String?): Boolean {
        if (uid < FIRST_APPLICATION_UID || packageName == null || !isValidPackageName(packageName)) return false
        val packages = runCatching {
            context.applicationContext.packageManager.getPackagesForUid(uid)
                ?.filter { it.isNotBlank() }
                ?.distinct()
                .orEmpty()
        }.getOrDefault(emptyList())
        return packages.size == 1 && packages.single() == packageName
    }

    private fun isValidPackageName(value: String): Boolean =
        value.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))

    private fun normalizeIp(value: String): String? {
        val raw = value.trim().substringBefore('%')
        if (raw.isBlank() || raw.contains('/') || raw.contains(' ')) return null
        // InetAddress.getByName is used only after requiring an IP-literal alphabet;
        // this prevents DNS resolution or hostnames from being accepted here.
        if (!raw.matches(Regex("[0-9A-Fa-f:.]{2,45}"))) return null
        return runCatching { InetAddress.getByName(raw).hostAddress?.substringBefore('%') }.getOrNull()
    }
}
