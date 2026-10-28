package com.hydra.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import com.hydra.firewall.security.LegacyTlsTrust
import com.hydra.firewall.security.ThreatIntelDomainStore
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.regex.Pattern
import javax.net.ssl.HttpsURLConnection

/**
 * Multi-source domain intelligence updater.
 *
 * The default balanced set is intentionally small enough for older Android
 * devices, while still combining independent sources:
 *   - Steven Black hosts (ads + malware)
 *   - HaGeZi Multi PRO mini (ads/trackers/privacy)
 *   - 1Hosts Lite (ads/trackers/malware)
 *   - HaGeZi Threat Intelligence Feeds mini (malware/phishing/C2)
 *
 * OISD Big is supported as an opt-in source through the public URL below.
 * The downloaded data is merged locally and the active set is replaced only
 * after all enabled sources that successfully downloaded produced enough data.
 */
object BlocklistUpdater {
    private const val TAG = "BlocklistUpdater"
    private const val CONNECT_TIMEOUT_MS = 12000
    private const val READ_TIMEOUT_MS = 30000
    private const val MAX_SOURCE_BYTES = 18L * 1024L * 1024L
    private const val MAX_COMBINED_DOMAINS = 900_000

    private val DATE_PATTERN = Pattern.compile("#\\s*(?:Date|Last modified):\\s*([^\\r\\n]+)")
    private val COUNT_PATTERN = Pattern.compile("#\\s*Number of (?:unique )?domains?:\\s*([0-9][0-9,]*)", Pattern.CASE_INSENSITIVE)
    private val HOST_PATTERN = Pattern.compile("^0\\.0\\.0\\.0\\s+([^\\s#]+)")
    private val DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9](?:[a-zA-Z0-9\\-_.]*[a-zA-Z0-9])?\\.[a-zA-Z]{2,63}$")
    private val ADGUARD_PATTERN = Pattern.compile("^\\|\\|([^\\^/]+)\\^.*$")
    private val WILDCARD_PATTERN = Pattern.compile("^\\*\\.([^\\s]+)$")
    private val EXCLUDED = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"
    )

    private val executor = Executors.newSingleThreadExecutor()

    data class Source(
        val id: String,
        val label: String,
        val urls: List<String>,
        val threatOnly: Boolean = false,
        val defaultEnabled: Boolean = true
    )

    private val sources = listOf(
        Source("stevenblack", "Steven Black", listOf(
            DomainBlockStore.REMOTE_HOSTS_URL,
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        )),
        Source("hagezi_pro_mini", "HaGeZi Multi PRO mini", listOf(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt"
        )),
        Source("1hosts_lite", "1Hosts Lite", listOf(
            "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt"
        )),
        Source("hagezi_tif_mini", "HaGeZi Threat Intelligence mini", listOf(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt"
        ), threatOnly = true),
        Source("oisd_big", "OISD Big", listOf("https://big.oisd.nl/"), defaultEnabled = false)
    )

    data class CheckResult(val remoteDate: String?, val remoteCount: Int?, val error: String?, val newAvailable: Boolean = false)

    private const val META_PREFS = "hydra_blocklist_meta"
    private const val META_PREFIX = "src_date_"

    /**
     * ¿Hay algo más nuevo que lo instalado? Se compara fuente por fuente (fecha remota vs. la fecha que
     * tenía esa misma fuente al instalar). Antes se comparaba la fecha de UNA fuente contra el texto que
     * unía las fechas de todas y el total de dominios combinado contra el de esa fuente: nunca coincidían,
     * y siempre decía "hay versión nueva". Sin metadatos guardados (instalación anterior) no hay con qué
     * comparar, así que se ofrece actualizar una vez; al aplicar se guardan y las siguientes comparaciones son exactas.
     */
    internal fun hasNewer(saved: Map<String, String>, remote: Map<String, String>): Boolean {
        if (remote.isEmpty()) return false
        return remote.any { (id, date) -> saved[id] != date }
    }

    private fun loadSavedDates(context: Context): Map<String, String> {
        val prefs = context.applicationContext.getSharedPreferences(META_PREFS, Context.MODE_PRIVATE)
        return prefs.all.filterKeys { it.startsWith(META_PREFIX) }
            .mapNotNull { (k, v) -> (v as? String)?.let { k.removePrefix(META_PREFIX) to it } }.toMap()
    }

    private fun saveDates(context: Context, results: List<SourceResult>) {
        val e = context.applicationContext.getSharedPreferences(META_PREFS, Context.MODE_PRIVATE).edit()
        results.forEach { r -> r.date?.let { e.putString(META_PREFIX + r.id, it) } }
        e.apply()
    }
    data class DownloadResult(val success: Boolean, val domainCount: Int, val remoteDate: String?, val error: String?, val skipped: Boolean = false)

    private fun enabledSources(): List<Source> {
        // Keep a simple balanced default. OISD Big is opt-in until a future UI
        // exposes per-source toggles and an explicit warning about wider scope.
        return sources.filter { it.defaultEnabled }
    }

    private fun configure(context: Context, conn: HttpsURLConnection): HttpsURLConnection = conn.apply {
        LegacyTlsTrust.configure(context.applicationContext, this)
        connectTimeout = CONNECT_TIMEOUT_MS
        readTimeout = READ_TIMEOUT_MS
        requestMethod = "GET"
        instanceFollowRedirects = false
        useCaches = false
        setRequestProperty("User-Agent", "Hydra-Firewall/${com.hydra.firewall.BuildConfig.VERSION_NAME}")
        setRequestProperty("Accept", "text/plain, text/x-hosts, */*")
        setRequestProperty("Cache-Control", "no-cache, no-store, max-age=0")
        setRequestProperty("Pragma", "no-cache")
        setRequestProperty("Accept-Encoding", "identity")
    }

    private fun physicalNetworks(context: Context): List<android.net.Network> {
        val cm = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) network else null
        }
    }

    private fun open(context: Context, urls: List<String>): HttpsURLConnection {
        var last: Throwable? = null
        for (network in physicalNetworks(context)) {
            for (raw in urls) {
                try {
                    val conn = configure(context, network.openConnection(URL(raw)) as HttpsURLConnection)
                    if (conn.url.protocol.equals("https", true)) return conn
                    conn.disconnect()
                } catch (t: Throwable) { last = t }
            }
        }
        for (raw in urls) {
            try {
                val conn = configure(context, URL(raw).openConnection() as HttpsURLConnection)
                if (conn.url.protocol.equals("https", true)) return conn
                conn.disconnect()
            } catch (t: Throwable) { last = t }
        }
        throw last ?: IllegalStateException("no_update_endpoint")
    }

    private data class SourceResult(val id: String, val label: String, val count: Int, val date: String?)

    private fun parseDomain(line: String): String? {
        var l = line.trim()
        if (l.isEmpty() || l.startsWith("#") || l.startsWith("!") || l.startsWith("[") || l.startsWith(";") ) return null
        if (l.startsWith("||")) {
            val m = ADGUARD_PATTERN.matcher(l)
            if (m.find()) l = m.group(1)
        } else if (l.startsWith("*.")) {
            val m = WILDCARD_PATTERN.matcher(l)
            if (m.find()) l = m.group(1)
        } else {
            val h = HOST_PATTERN.matcher(l)
            if (h.find()) l = h.group(1)
            else l = l.split(Regex("\\s+"))[0]
        }
        l = l.trim().trimEnd('.').lowercase()
        if (l in EXCLUDED) return null
        if (l.contains('/') || l.contains(':') || l.contains(' ')) return null
        if (!DOMAIN_PATTERN.matcher(l).matches()) return null
        return l
    }

    private fun downloadSource(context: Context, source: Source): SourceResult {
        var last: Throwable? = null
        for (networkAttempt in 0..physicalNetworks(context).size) {
            try {
                val conn = open(context, source.urls)
                try {
                    val code = conn.responseCode
                    if (code !in 200..299) throw IllegalStateException("${source.id}_http_$code")
                    val length = conn.contentLengthLong
                    if (length > MAX_SOURCE_BYTES) throw IllegalStateException("${source.id}_too_large")
                    var date: String? = null
                    var count = 0
                    val unique = HashSet<String>(16_384)
                    BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8)).use { reader ->
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.length > 4096) continue
                            if (date == null) {
                                val m = DATE_PATTERN.matcher(line)
                                if (m.find()) date = m.group(1)?.trim()
                            }
                            val d = parseDomain(line) ?: continue
                            if (unique.add(d)) count++
                            if (count > MAX_COMBINED_DOMAINS) throw IllegalStateException("${source.id}_too_large")
                        }
                    }
                    if (count < 1000) throw IllegalStateException("${source.id}_implausibly_small:$count")
                    return SourceResult(source.id, source.label, count, date)
                } finally { conn.disconnect() }
            } catch (t: Throwable) {
                last = t
                Log.w(TAG, "Source failed: ${source.id}", t)
            }
        }
        throw last ?: IllegalStateException("${source.id}_failed")
    }

    private fun readSourceIntoSet(context: Context, source: Source, merged: MutableSet<String>, threatDomains: MutableSet<String>? = null): SourceResult {
        val result = downloadSourceToSet(context, source, merged, threatDomains)
        return result
    }

    private fun downloadSourceToSet(context: Context, source: Source, merged: MutableSet<String>, threatDomains: MutableSet<String>? = null): SourceResult {
        var last: Throwable? = null
        for (raw in source.urls) {
            try {
                val conn = open(context, listOf(raw))
                try {
                    val code = conn.responseCode
                    if (code !in 200..299) throw IllegalStateException("${source.id}_http_$code")
                    val length = conn.contentLengthLong
                    if (length > MAX_SOURCE_BYTES) throw IllegalStateException("${source.id}_too_large")
                    var date: String? = null
                    var added = 0
                    BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8)).use { reader ->
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.length > 4096) continue
                            if (date == null) DATE_PATTERN.matcher(line).takeIf { it.find() }?.let { date = it.group(1)?.trim() }
                            val d = parseDomain(line) ?: continue
                            if (merged.add(d)) added++
                            if (source.threatOnly) threatDomains?.add(d)
                            if (merged.size > MAX_COMBINED_DOMAINS) throw IllegalStateException("combined_list_too_large")
                        }
                    }
                    if (added < 1000) throw IllegalStateException("${source.id}_implausibly_small:$added")
                    return SourceResult(source.id, source.label, added, date)
                } finally { conn.disconnect() }
            } catch (t: Throwable) {
                last = t
                Log.w(TAG, "Source endpoint failed: ${source.id} $raw", t)
            }
        }
        throw last ?: IllegalStateException("${source.id}_failed")
    }

    fun checkForUpdate(context: Context, callback: (CheckResult) -> Unit) {
        executor.execute {
            var lastError: Throwable? = null
            val remoteDates = LinkedHashMap<String, String>()
            for (source in enabledSources()) {
                try {
                    val conn = open(context, source.urls)
                    try {
                        val code = conn.responseCode
                        if (code !in 200..299) throw IllegalStateException("${source.id}_http_$code")
                        var remoteDate: String? = null
                        BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8)).use { reader ->
                            var n = 0
                            while (n < 120 && remoteDate == null) {
                                val line = reader.readLine() ?: break
                                n++
                                DATE_PATTERN.matcher(line).takeIf { it.find() }?.let { remoteDate = it.group(1)?.trim() }
                            }
                        }
                        // Una fuente sin fecha en su cabecera no puede compararse: se ignora.
                        remoteDate?.let { remoteDates[source.id] = it }
                    } finally { conn.disconnect() }
                } catch (t: Throwable) {
                    lastError = t
                    Log.w(TAG, "Blocklist update check failed for ${source.id}", t)
                }
            }
            if (remoteDates.isEmpty()) {
                callback(CheckResult(null, null, lastError?.message ?: lastError?.javaClass?.simpleName ?: "date_not_found"))
            } else {
                val newer = hasNewer(loadSavedDates(context), remoteDates)
                callback(CheckResult(remoteDates.values.joinToString(" | ").take(240), null, null, newer))
            }
        }
    }

    fun downloadAndApply(context: Context, callback: (DownloadResult) -> Unit) {
        executor.execute {
            val result = runCatching {
                val merged = LinkedHashSet<String>(160_000)
                val threatDomains = LinkedHashSet<String>(16_384)
                val successful = mutableListOf<SourceResult>()
                var failures = 0
                for (source in enabledSources()) {
                    try {
                        successful += readSourceIntoSet(context, source, merged, threatDomains.takeIf { source.threatOnly })
                    } catch (t: Throwable) {
                        failures++
                        Log.w(TAG, "Enabled source skipped: ${source.id}", t)
                    }
                }
                if (successful.isEmpty() || merged.size < 1000) throw IllegalStateException("all_blocklist_sources_failed")
                val sourceLabel = successful.joinToString(" + ") { it.label }
                val remoteDate = successful.mapNotNull { it.date }.joinToString(" | ").take(240)
                val local = DomainBlockStore.activeListInfo()
                if (local.domainCount == merged.size && local.source == sourceLabel && DomainBlockStore.activeListUsable() &&
                    ThreatIntelDomainStore.info(context).count > 0) {
                    saveDates(context, successful)
                    return@runCatching DownloadResult(true, local.domainCount, remoteDate, if (failures > 0) "partial_sources" else null, skipped = true)
                }
                val applied = DomainBlockStore.applyDownloadedList(merged.toList(), remoteDate, sourceLabel)
                if (!applied) throw IllegalStateException("apply_failed")
                if (threatDomains.size >= 100) {
                    ThreatIntelDomainStore.install(context.applicationContext, threatDomains, "HaGeZi Threat Intelligence mini", remoteDate)
                }
                val active = DomainBlockStore.activeListInfo()
                if (!DomainBlockStore.activeListUsable() || active.domainCount != merged.size || active.source != sourceLabel) {
                    throw IllegalStateException("apply_verification_failed")
                }
                saveDates(context, successful)
                DownloadResult(true, merged.size, remoteDate, if (failures > 0) "partial_sources:${failures}" else null)
            }.getOrElse { e ->
                Log.w(TAG, "Blocklist download failed", e)
                DownloadResult(false, 0, null, e.message ?: e.javaClass.simpleName)
            }
            callback(result)
        }
    }
}
