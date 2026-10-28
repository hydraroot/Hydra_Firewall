package com.hydra.firewall.security

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipFile

/**
 * Local threat-signature database. It never trusts a downloaded pack until the
 * asymmetric signature has been verified by [ThreatSignatureVerifier].
 */
object ThreatSignatureStore {
    private const val TAG = "ThreatSignatureStore"
    private const val ASSET_PACK = "hydra_threat_pack_v1.json"
    private const val ACTIVE_FILE = "hydra_threat_pack_v1.json"
    private const val PREFS = "hydra_threat_signatures"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_BLOCK_NETWORK = "block_network"
    private const val KEY_LAST_ERROR = "last_error"
    private const val KEY_LAST_UPDATE = "last_update"
    private const val KEY_DAILY_BLOCKS = "daily_blocks"
    private const val KEY_DAILY_DATE = "daily_date"
    private const val MAX_HASHES = 500_000
    private const val MAX_DOMAINS = 500_000
    private const val MAX_IPS = 250_000
    private const val MAX_URLS = 250_000
    private const val MAX_YARA_RULES = 5_000
    private val initialized = AtomicBoolean(false)
    private val active = AtomicReference(Pack.empty())
    private val contextRef = AtomicReference<Context?>(null)
    private val dailyBlocks = AtomicReference(0L)

    data class Pack(
        val version: String,
        val generatedAt: Long,
        val expiresAt: Long,
        val sha256: Map<String, ThreatSignatureMatch>,
        val domains: Map<String, ThreatSignatureMatch>,
        val ips: Map<String, ThreatSignatureMatch>,
        val urls: Map<String, ThreatSignatureMatch>,
        val yara: List<HydraYaraLite.Rule>,
        val sourceSummary: List<String>
    ) {
        companion object { fun empty() = Pack("bundled-0", 0L, 0L, emptyMap(), emptyMap(), emptyMap(), emptyMap(), emptyList(), emptyList()) }
    }

    data class NetworkMatch(val match: ThreatSignatureMatch, val normalized: String)

    fun init(context: Context) {
        contextRef.set(context.applicationContext)
        ThreatIntelDomainStore.init(context.applicationContext)
        if (initialized.compareAndSet(false, true)) {
            loadBestPack(context.applicationContext)
            refreshDailyCounter(context.applicationContext)
        } else if (active.get() == Pack.empty()) {
            loadBestPack(context.applicationContext)
        }
    }

    fun isEnabled(context: Context? = null): Boolean = prefs(context).getBoolean(KEY_ENABLED, true)
    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun isNetworkBlockEnabled(context: Context? = null): Boolean = prefs(context).getBoolean(KEY_BLOCK_NETWORK, true)
    fun setNetworkBlockEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_BLOCK_NETWORK, enabled).apply()
    }

    fun status(context: Context): ThreatSignatureStatus {
        init(context)
        val p = active.get()
        val liveThreat = ThreatIntelDomainStore.info(context)
        return ThreatSignatureStatus(
            enabled = isEnabled(context),
            packVersion = p.version,
            generatedAt = p.generatedAt,
            expiresAt = p.expiresAt,
            sha256Count = p.sha256.size,
            domainCount = p.domains.size,
            ipCount = p.ips.size,
            urlCount = p.urls.size,
            yaraRuleCount = p.yara.size,
            liveThreatDomainCount = liveThreat.count,
            liveThreatSource = liveThreat.source,
            sourceSummary = p.sourceSummary,
            lastUpdateError = prefs(context).getString(KEY_LAST_ERROR, null)
        )
    }

    fun activePackVersion(): String = active.get().version

    fun lookupSha256(context: Context, hash: String): ThreatSignatureMatch? {
        init(context)
        if (!isEnabled(context)) return null
        return active.get().sha256[hash.trim().lowercase(Locale.US)]
    }

    fun matchDomain(context: Context, domain: String): NetworkMatch? {
        init(context)
        if (!isEnabled(context) || !isNetworkBlockEnabled(context)) return null
        val normalized = normalizeDomain(domain)
        if (normalized.isEmpty()) return null
        if (ThreatIntelDomainStore.match(normalized)) {
            val live = ThreatSignatureMatch(
                kind = ThreatSignatureMatch.Kind.DOMAIN,
                name = normalized,
                family = "Threat Intelligence",
                source = ThreatIntelDomainStore.info(context).source.ifBlank { "Hydra Threat Intelligence" },
                severity = Severity.HIGH,
                confidence = 90,
                detail = "Known threat-intelligence domain"
            )
            return NetworkMatch(live, normalized)
        }
        val map = active.get().domains
        map[normalized]?.let { return NetworkMatch(it, normalized) }
        var current = normalized
        while (current.contains('.')) {
            current = current.substringAfter('.')
            if (current.isBlank() || current == normalized) break
            map[current]?.let { return NetworkMatch(it, normalized) }
        }
        return null
    }

    fun matchIp(context: Context, ip: String): NetworkMatch? {
        init(context)
        if (!isEnabled(context) || !isNetworkBlockEnabled(context)) return null
        val normalized = ip.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        val match = active.get().ips[normalized] ?: return null
        return NetworkMatch(match, normalized)
    }

    fun matchUrl(context: Context, url: String): NetworkMatch? {
        init(context)
        if (!isEnabled(context) || !isNetworkBlockEnabled(context)) return null
        val normalized = url.trim().lowercase(Locale.US)
        return active.get().urls[normalized]?.let { NetworkMatch(it, normalized) }
    }

    fun recordNetworkBlock(context: Context) {
        init(context)
        refreshDailyCounter(context)
        dailyBlocks.getAndUpdate { it + 1L }
        prefs(context).edit().putLong(KEY_DAILY_BLOCKS, dailyBlocks.get()).apply()
    }

    fun blockedToday(context: Context): Long {
        init(context)
        refreshDailyCounter(context)
        return dailyBlocks.get()
    }

    fun scanApk(context: Context, file: File, splitFiles: List<File> = emptyList()): List<ThreatSignatureMatch> {
        init(context)
        if (!isEnabled(context)) return emptyList()
        val matches = mutableListOf<ThreatSignatureMatch>()
        val hash = sha256(file)
        active.get().sha256[hash]?.let { matches += it }
        matches += HydraYaraLite.scanApk(file, active.get().yara)
        for (split in splitFiles) {
            if (!split.isFile || !split.canRead()) continue
            val splitHash = sha256(split)
            active.get().sha256[splitHash]?.let { matches += it.copy(detail = "${it.detail} • split ${split.name}") }
            matches += HydraYaraLite.scanApk(split, active.get().yara)
        }
        return matches.distinctBy { "${it.kind}:${it.name}:${it.family}:${it.detail}" }
    }

    /** Replace the active pack only after full cryptographic and structural validation. */
    fun installVerifiedPack(context: Context, envelopeText: String): Boolean {
        init(context)
        val payload = ThreatSignatureVerifier.verifyAndExtract(envelopeText) ?: return false
        val parsed = parsePayload(payload) ?: return false
        val now = System.currentTimeMillis()
        if (parsed.generatedAt <= 0L) return false
        if (parsed.expiresAt > 0L && parsed.expiresAt < now) return false
        if (parsed.expiresAt > 0L && parsed.expiresAt < parsed.generatedAt) return false
        val currentGeneratedAt = active.get().generatedAt
        if (currentGeneratedAt > 0L && parsed.generatedAt < currentGeneratedAt) return false
        if (parsed.sha256.size > MAX_HASHES || parsed.domains.size > MAX_DOMAINS || parsed.ips.size > MAX_IPS || parsed.urls.size > MAX_URLS || parsed.yara.size > MAX_YARA_RULES) return false

        val target = File(context.filesDir, ACTIVE_FILE)
        val temp = File(context.filesDir, "$ACTIVE_FILE.tmp")
        val backup = File(context.filesDir, "$ACTIVE_FILE.bak")
        return runCatching {
            temp.writeText(envelopeText, Charsets.UTF_8)

            if (target.exists()) {
                target.copyTo(backup, overwrite = true)
                if (!target.delete() && target.exists()) {
                    throw IllegalStateException("target_delete_failed")
                }
            }

            if (!temp.renameTo(target)) {
                if (backup.isFile && !target.exists()) {
                    runCatching { backup.copyTo(target, overwrite = true) }
                }
                throw IllegalStateException("atomic_rename_failed")
            }

            // Re-read and re-verify the exact bytes that became active.
            val installedEnvelope = target.readText(Charsets.UTF_8)
            val installedPayload = ThreatSignatureVerifier.verifyAndExtract(installedEnvelope)
                ?: throw IllegalStateException("installed_signature_invalid")
            val installedPack = parsePayload(installedPayload)
                ?: throw IllegalStateException("installed_pack_invalid")
            if (installedPack.generatedAt != parsed.generatedAt || installedPack.version != parsed.version) {
                throw IllegalStateException("installed_pack_mismatch")
            }

            active.set(installedPack)
            prefs(context).edit()
                .putString(KEY_LAST_ERROR, null)
                .putLong(KEY_LAST_UPDATE, now)
                .apply()
            true
        }.onFailure {
            Log.w(TAG, "Unable to install threat pack", it)
            runCatching { temp.delete() }
            if (!target.exists() && backup.isFile) {
                runCatching { backup.copyTo(target, overwrite = true) }
            }
        }.getOrDefault(false)
    }

    fun markUpdateError(context: Context, error: String?) {
        prefs(context).edit().putString(KEY_LAST_ERROR, error?.take(300)).apply()
    }

    fun lastUpdate(context: Context): Long = prefs(context).getLong(KEY_LAST_UPDATE, 0L)

    private fun loadBestPack(context: Context) {
        val bundledText = runCatching {
            context.assets.open(ASSET_PACK).bufferedReader(Charsets.UTF_8).use { it.readText() }
        }.getOrNull()
        val activeFile = File(context.filesDir, ACTIVE_FILE)
        val backupFile = File(context.filesDir, "$ACTIVE_FILE.bak")
        val diskText = runCatching { if (activeFile.isFile) activeFile.readText(Charsets.UTF_8) else null }.getOrNull()
        val backupText = runCatching { if (backupFile.isFile) backupFile.readText(Charsets.UTF_8) else null }.getOrNull()
        val candidates = listOfNotNull(diskText, backupText, bundledText)
        val parsed = candidates.asSequence()
            .mapNotNull { ThreatSignatureVerifier.verifyAndExtract(it)?.let(::parsePayload) }
            .filter { it.expiresAt <= 0L || it.expiresAt >= System.currentTimeMillis() }
            .maxByOrNull { it.generatedAt }
        active.set(parsed ?: Pack.empty())
    }

    private fun parsePayload(payload: String): Pack? = runCatching {
        val root = JSONObject(payload)
        require(root.optInt("schema", 0) == 1)
        val version = root.optString("pack_version", "").trim()
        val generatedAt = root.optLong("generated_at", 0L)
        val expiresAt = root.optLong("expires_at", 0L)
        require(version.isNotBlank())
        require(generatedAt > 0L)
        require(expiresAt <= 0L || expiresAt >= generatedAt)
        val hashes = parseIndicatorArray(root.optJSONArray("sha256"), ThreatSignatureMatch.Kind.SHA256)
        val domains = parseIndicatorArray(root.optJSONArray("domains"), ThreatSignatureMatch.Kind.DOMAIN)
        val ips = parseIndicatorArray(root.optJSONArray("ips"), ThreatSignatureMatch.Kind.IP)
        val urls = parseIndicatorArray(root.optJSONArray("urls"), ThreatSignatureMatch.Kind.URL)
        val yaraRules = mutableListOf<HydraYaraLite.Rule>()
        val yara = root.optJSONArray("yara_rules") ?: JSONArray()
        for (i in 0 until yara.length()) {
            val source = yara.optJSONObject(i)?.optString("source").orEmpty()
            if (source.isNotBlank()) yaraRules += HydraYaraLite.parse(source)
        }
        val sourceSummary = root.optJSONArray("sources")?.let { arr -> (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() } }.orEmpty()
        Pack(version, generatedAt, expiresAt, hashes, domains, ips, urls, yaraRules, sourceSummary)
    }.getOrElse { e ->
        Log.w(TAG, "Invalid threat payload", e)
        null
    }

    private fun parseIndicatorArray(array: JSONArray?, kind: ThreatSignatureMatch.Kind): Map<String, ThreatSignatureMatch> {
        if (array == null) return emptyMap()
        val out = HashMap<String, ThreatSignatureMatch>(array.length())
        for (i in 0 until array.length()) {
            val o = array.optJSONObject(i) ?: continue
            val value = o.optString("value").trim().lowercase(Locale.US)
            if (value.isBlank()) continue
            val severity = o.optInt("severity", 70).coerceIn(0, 100)
            val match = ThreatSignatureMatch(
                kind = kind,
                name = o.optString("name", value.take(80)),
                family = o.optString("family", null),
                source = o.optString("source", "Hydra Threat Signatures"),
                severity = when {
                    severity >= 90 -> Severity.CRITICAL
                    severity >= 70 -> Severity.HIGH
                    severity >= 40 -> Severity.MEDIUM
                    else -> Severity.LOW
                },
                confidence = o.optInt("confidence", severity).coerceIn(0, 100),
                detail = o.optString("detail", "Threat intelligence match")
            )
            out[value] = match
        }
        return out
    }

    private fun normalizeDomain(input: String): String = input.trim().trimEnd('.').lowercase(Locale.US).removePrefix(".")

    private fun prefs(context: Context?): android.content.SharedPreferences {
        val c = context?.applicationContext ?: contextRef.get() ?: throw IllegalStateException("ThreatSignatureStore not initialized")
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    private fun refreshDailyCounter(context: Context) {
        val prefs = prefs(context)
        val today = java.text.SimpleDateFormat("yyyy-MM-dd", Locale.US).format(java.util.Date())
        val stored = prefs.getString(KEY_DAILY_DATE, null)
        if (stored != today) {
            dailyBlocks.set(0L)
            prefs.edit().putString(KEY_DAILY_DATE, today).putLong(KEY_DAILY_BLOCKS, 0L).apply()
        } else {
            dailyBlocks.set(prefs.getLong(KEY_DAILY_BLOCKS, 0L))
        }
    }

    private fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
