package com.hydra.firewall.vpn

import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.GZIPInputStream

/**
 * Local domain blocklist for ad/tracker blocking, matched against outgoing
 * DNS queries before they leave the device. No traffic is redirected to any
 * third-party server for this feature: the list is read from disk (bundled
 * asset or a file the user explicitly downloaded) and matching is a local
 * in-memory lookup.
 *
 * Attribution: the bundled list is a license-compatible-only bundle (MIT /
 * CC0-1.0 / CC BY 3.0 / CC BY 4.0 sources — StevenBlack's ad-hoc list, AdAway,
 * FadeMind hosts.extras, Badd-Boyz-Hosts, hostsVN, minecraft-hosts trackers,
 * Tiuxo ads, UncheckyAds). It intentionally excludes StevenBlack/hosts'
 * unified variant and its non-commercial (MVPS, Dan Pollock) and share-alike
 * (KADhosts) upstream sources, and pgl.yoyo.org (no declared license), none
 * of which can be redistributed inside this GPL-3.0 APK. See
 * THIRD_PARTY_NOTICES.md and the "Acerca de" screen for the full notice.
 */
object DomainBlockStore {
    private const val TAG = "DomainBlockStore"
    private const val ASSET_LIST = "blocklist.txt.gz"
    private const val ASSET_META = "blocklist_meta.json"
    private const val DOWNLOADED_LIST_FILENAME = "blocklist_downloaded.txt"
    private const val PREFS_NAME = "firewall_domain_block"
    private const val KEY_ENABLED = "domain_block_enabled"
    private const val KEY_ACTIVE_DATE = "active_list_date"
    private const val KEY_ACTIVE_COUNT = "active_list_domain_count"
    private const val KEY_ACTIVE_SOURCE = "active_list_source"
    private const val KEY_BLOCKED_TODAY_COUNT = "blocked_today_count"
    private const val KEY_BLOCKED_TODAY_DATE = "blocked_today_date"

    // "Update now" downloads this directly from StevenBlack's GitHub to the
    // device; the app never bundles or redistributes it, so the stricter
    // upstream licenses (MVPS/Pollock non-commercial, KADhosts share-alike)
    // apply only between StevenBlack and the user, not to this APK.
    const val REMOTE_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    const val SOURCE_LABEL = "StevenBlack/hosts (adware + malware, downloaded on demand)"
    const val SOURCE_PAGE_URL = "https://github.com/StevenBlack/hosts"
    const val LICENSE_LABEL = "Mixed upstream licenses (MIT, CC BY, non-commercial, share-alike) — downloaded directly from StevenBlack, not redistributed by this app"

    data class ListInfo(val date: String, val domainCount: Int, val source: String)

    private val initialized = AtomicBoolean(false)
    private val domains = AtomicReference<HashSet<String>>(HashSet())
    private val blockedTodayCount = AtomicReference(0L)
    private val appContextRef = AtomicReference<Context?>(null)

    @Synchronized
    fun init(context: Context) {
        appContextRef.set(context.applicationContext)
        if (!initialized.compareAndSet(false, true)) {
            // If an earlier entry point initialized the singleton while the
            // asset was not yet readable, retry instead of permanently
            // leaving the UI with an empty/zero-domain list.
            if (domains.get().isEmpty()) loadActiveList()
            refreshTodayCounterIfNewDay()
            return
        }
        loadActiveList()
        refreshTodayCounterIfNewDay()
    }

    /**
     * Every public property/function below goes through this instead of a
     * `lateinit var`. If something reads state before [init] has ever run
     * (e.g. a future entry point added ahead of the store's initialization),
     * this returns null and callers fail safe (feature reads as disabled /
     * empty) instead of crashing the app with an uninitialized-property
     * exception.
     */
    private fun ctxOrNull(): Context? = appContextRef.get()

    private val prefsOrNull: android.content.SharedPreferences?
        get() = ctxOrNull()?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var enabled: Boolean
        get() = prefsOrNull?.getBoolean(KEY_ENABLED, false) ?: false
        set(value) { prefsOrNull?.edit()?.putBoolean(KEY_ENABLED, value)?.apply() }

    /** True if a downloaded (user-updated) list file exists and is in use. */
    fun usingDownloadedList(): Boolean {
        val prefs = prefsOrNull ?: return false
        return downloadedListFile()?.exists() == true && prefs.getString(KEY_ACTIVE_SOURCE, "") == "downloaded"
    }

    fun activeListInfo(): ListInfo {
        val prefs = prefsOrNull ?: return ListInfo("", 0, "bundled")
        return ListInfo(
            date = prefs.getString(KEY_ACTIVE_DATE, "") ?: "",
            domainCount = prefs.getInt(KEY_ACTIVE_COUNT, 0),
            source = prefs.getString(KEY_ACTIVE_SOURCE, "bundled") ?: "bundled"
        )
    }

    /** True only when a non-empty list is actually loaded in memory and can be matched. */
    fun activeListUsable(): Boolean = domains.get().isNotEmpty()


    fun blockedToday(): Long {
        if (ctxOrNull() == null) return 0L
        refreshTodayCounterIfNewDay()
        return blockedTodayCount.get()
    }

    private fun refreshTodayCounterIfNewDay() {
        val prefs = prefsOrNull ?: return
        val today = todayKey()
        val storedDate = prefs.getString(KEY_BLOCKED_TODAY_DATE, "")
        if (storedDate != today) {
            prefs.edit().putString(KEY_BLOCKED_TODAY_DATE, today).putLong(KEY_BLOCKED_TODAY_COUNT, 0L).apply()
            blockedTodayCount.set(0L)
        } else {
            blockedTodayCount.set(prefs.getLong(KEY_BLOCKED_TODAY_COUNT, 0L))
        }
    }

    private fun todayKey(): String {
        val cal = java.util.Calendar.getInstance()
        return "${cal.get(java.util.Calendar.YEAR)}-${cal.get(java.util.Calendar.DAY_OF_YEAR)}"
    }

    /**
     * Igual que [isBlocked] pero SOLO LEE: no suma al contador "bloqueados hoy". Sirve para EXPLICAR una
     * conexión en pantalla sin inflar las estadísticas.
     */
    fun matchesWithoutCounting(domain: String): Boolean {
        if (ctxOrNull() == null || !enabled) return false
        val set = domains.get()
        if (set.isEmpty()) return false
        var d = domain.trim().trimEnd('.').lowercase()
        if (d.isEmpty()) return false
        while (true) {
            if (set.contains(d)) return true
            val dot = d.indexOf('.')
            if (dot < 0) return false
            d = d.substring(dot + 1)
            if (d.isEmpty() || !d.contains('.')) return false
        }
    }

    /**
     * Checks a query domain against the active blocklist, matching the exact
     * domain or any of its parent domains (so a rule for "example.com" also
     * covers "ads.example.com"). O(1) HashSet lookups, at most a handful per
     * query (one per label level), so this is negligible on the UDP selector
     * thread. Fails safe (never blocks) if the store hasn't been initialized
     * on this process yet.
     */
    fun isBlocked(domain: String): Boolean {
        if (ctxOrNull() == null) return false
        if (!enabled) return false
        val set = domains.get()
        if (set.isEmpty()) return false
        var d = domain.trim().trimEnd('.').lowercase()
        if (d.isEmpty()) return false
        while (true) {
            if (set.contains(d)) {
                val today = todayKey()
                val prefs = prefsOrNull
                if (prefs != null && prefs.getString(KEY_BLOCKED_TODAY_DATE, "") != today) refreshTodayCounterIfNewDay()
                val updated = blockedTodayCount.get() + 1
                blockedTodayCount.set(updated)
                prefs?.edit()?.putLong(KEY_BLOCKED_TODAY_COUNT, updated)?.apply()
                return true
            }
            val dot = d.indexOf('.')
            if (dot < 0) return false
            d = d.substring(dot + 1)
            if (d.isEmpty() || !d.contains('.')) return false // stop at bare TLD
        }
    }

    private fun downloadedListFile(): File? = ctxOrNull()?.let { File(it.filesDir, DOWNLOADED_LIST_FILENAME) }
    private fun downloadedMetaFile(): File? = ctxOrNull()?.let { File(it.filesDir, "$DOWNLOADED_LIST_FILENAME.meta") }

    private fun loadActiveList() {
        val downloaded = downloadedListFile()
        val meta = downloadedMetaFile()
        val prefs = prefsOrNull
        if (downloaded != null && meta != null && prefs != null && downloaded.exists() && meta.exists()) {
            val loaded = runCatching {
                val date = meta.readText().trim()
                val set = HashSet<String>(120_000)
                var count = 0
                downloaded.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        val d = line.trim()
                        if (d.isEmpty()) continue
                        set.add(d)
                        count++
                    }
                }
                Triple(set, date, count)
            }.getOrNull()
            if (loaded != null) {
                domains.set(loaded.first)
                prefs.edit()
                    .putString(KEY_ACTIVE_DATE, loaded.second)
                    .putInt(KEY_ACTIVE_COUNT, loaded.third)
                    .putString(KEY_ACTIVE_SOURCE, "downloaded")
                    .apply()
                return
            }
            Log.w(TAG, "Downloaded blocklist unreadable, falling back to bundled asset")
        }
        loadBundledAsset()
    }

    private fun loadBundledAsset() {
        val context = ctxOrNull() ?: return
        val prefs = prefsOrNull ?: return
        val loaded = runCatching {
            val metaJson = context.assets.open(ASSET_META).bufferedReader().use { it.readText() }
            val date = Regex("\"listDate\"\\s*:\\s*\"([^\"]+)\"").find(metaJson)?.groupValues?.get(1) ?: ""
            val set = HashSet<String>(120_000)
            var count = 0
            GZIPInputStream(context.assets.open(ASSET_LIST)).bufferedReader().useLines { lines ->
                for (line in lines) {
                    val d = line.trim()
                    if (d.isEmpty()) continue
                    set.add(d)
                    count++
                }
            }
            Pair(set, date to count)
        }.getOrNull()
        if (loaded != null) {
            domains.set(loaded.first)
            prefs.edit()
                .putString(KEY_ACTIVE_DATE, loaded.second.first)
                .putInt(KEY_ACTIVE_COUNT, loaded.second.second)
                .putString(KEY_ACTIVE_SOURCE, "bundled")
                .apply()
        } else {
            Log.e(TAG, "Failed to load bundled blocklist asset")
        }
    }

    /** Bundled asset's own date, for comparison against a remote check result. */
    fun bundledListDate(): String {
        val context = ctxOrNull() ?: return ""
        return runCatching {
            val metaJson = context.assets.open(ASSET_META).bufferedReader().use { it.readText() }
            Regex("\"listDate\"\\s*:\\s*\"([^\"]+)\"").find(metaJson)?.groupValues?.get(1) ?: ""
        }.getOrDefault("")
    }

    /**
     * Replaces the active list with newly downloaded, cleaned domain lines
     * (one domain per line, already parsed by the caller) plus the remote
     * list's date. Called only after the user explicitly requests an update
     * and confirms; never invoked automatically.
     */
    @Synchronized
    fun applyDownloadedList(domainLines: List<String>, remoteDate: String): Boolean =
        applyDownloadedList(domainLines, remoteDate, "downloaded")

    @Synchronized
    fun applyDownloadedList(domainLines: List<String>, remoteDate: String, sourceLabel: String): Boolean {
        val file = downloadedListFile() ?: return false
        val metaFile = downloadedMetaFile() ?: return false
        val prefs = prefsOrNull ?: return false
        return runCatching {
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.bufferedWriter().use { w ->
                for (d in domainLines) {
                    w.write(d)
                    w.write("\n")
                }
            }
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
            metaFile.writeText(remoteDate)
            val set = HashSet<String>(domainLines.size + 1024)
            set.addAll(domainLines)
            if (set.isEmpty()) throw IllegalStateException("empty_active_list")
            domains.set(set)
            prefs.edit()
                .putString(KEY_ACTIVE_DATE, remoteDate)
                .putInt(KEY_ACTIVE_COUNT, set.size)
                .putString(KEY_ACTIVE_SOURCE, sourceLabel.ifBlank { "downloaded" })
                .apply()
            true
        }.getOrElse { e ->
            Log.e(TAG, "Failed to apply downloaded blocklist", e)
            false
        }
    }
}
