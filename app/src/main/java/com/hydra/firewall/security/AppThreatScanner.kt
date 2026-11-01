package com.hydra.firewall.security

import android.content.Context
import android.content.pm.ApplicationInfo
import com.hydra.firewall.vpn.NotificationHelper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Antivirus-style check of the installed apps against the signed threat pack (known-malware SHA-256 hashes and
 * YARA-Lite patterns). It runs by itself when an app is installed or updated and when a new pack is downloaded,
 * and on demand. It is light (no machine-learning model, no DEX parsing) so it can run in the background.
 *
 * It only finds what is in the pack. It never uninstalls or blocks anything by itself: it records the finding,
 * raises a notification and lets the user decide.
 */
object AppThreatScanner {
    data class Finding(
        val packageName: String,
        val label: String,
        val matches: List<ThreatSignatureMatch>,
        val time: Long
    ) {
        /** A hash match means "this exact file is known malware"; a YARA match is only a suspicious pattern. */
        val definitive: Boolean get() = matches.any { it.kind == ThreatSignatureMatch.Kind.SHA256 }
        val worstSeverity: Severity get() = matches.maxByOrNull { it.severity.ordinal }?.severity ?: Severity.INFO
    }

    private const val PREFS = "hydra_app_threat_scan"
    private const val KEY_AUTO = "auto_enabled"
    private const val KEY_LAST_FULL = "last_full_scan"
    private const val KEY_LAST_PACK = "last_full_scan_pack"
    private const val KEY_FINDINGS = "findings"
    private const val KEY_IGNORED = "ignored"
    private const val SEEN_PREFIX = "seen_"
    private const val MAX_FINDINGS = 100
    private const val MAX_APK_BYTES = 512L * 1024L * 1024L

    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "hydra-app-threat-scan").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }
    }
    private val fullScanRunning = AtomicBoolean(false)
    @Volatile private var progressDone = 0
    @Volatile private var progressTotal = 0

    /** (checked so far, total) of the full scan that is running; (0,0) when idle. */
    fun progress(): Pair<Int, Int> = progressDone to progressTotal

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isAutoEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_AUTO, true)
    fun setAutoEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO, enabled).apply()
    }

    fun isFullScanRunning(): Boolean = fullScanRunning.get()
    fun lastFullScan(context: Context): Long = prefs(context).getLong(KEY_LAST_FULL, 0L)
    fun lastFullScanPack(context: Context): String = prefs(context).getString(KEY_LAST_PACK, "").orEmpty()

    fun findings(context: Context): List<Finding> =
        decodeFindings(prefs(context).getString(KEY_FINDINGS, "[]").orEmpty())

    // ---- ignore list ------------------------------------------------------------------------------------

    fun ignoredFindings(context: Context): List<Finding> =
        decodeFindings(prefs(context).getString(KEY_IGNORED, "[]").orEmpty())

    /** Same app + same set of matching rules. If the app later matches something different, it is reported again. */
    internal fun ruleKey(f: Finding): String = f.matches.map { it.name }.sorted().joinToString("|")

    fun isIgnored(context: Context, f: Finding): Boolean =
        ignoredFindings(context).any { it.packageName == f.packageName && ruleKey(it) == ruleKey(f) }

    /** The user looked into it and decided it is not a problem: move it from findings to the ignored list. */
    @Synchronized
    fun ignore(context: Context, f: Finding) {
        val app = context.applicationContext
        val ignored = listOf(f) + ignoredFindings(app).filterNot { it.packageName == f.packageName }
        val kept = findings(app).filterNot { it.packageName == f.packageName }
        prefs(app).edit().putString(KEY_IGNORED, encodeFindings(ignored)).putString(KEY_FINDINGS, encodeFindings(kept)).apply()
        SecurityEventStore.record(app, "APP_THREAT_IGNORED", "Ignored: ${f.label}", f.packageName, Severity.INFO)
    }

    /** Watch the app again: it is checked right away and reported if it still matches. */
    @Synchronized
    fun unignore(context: Context, packageName: String) {
        val app = context.applicationContext
        val ignored = ignoredFindings(app).filterNot { it.packageName == packageName }
        prefs(app).edit().putString(KEY_IGNORED, encodeFindings(ignored)).apply()
        executor.execute {
            runCatching {
                recordResult(app, packageName, scanOne(app, packageName))
                markSeen(app, packageName)
            }
        }
    }

    // ---- triggers ---------------------------------------------------------------------------------------

    /** An app was installed or updated: check just that app (if automatic checks are on). */
    fun onPackageChanged(context: Context, packageName: String) {
        val app = context.applicationContext
        if (!isAutoEnabled(app) || packageName == app.packageName) return
        executor.execute {
            runCatching {
                val finding = scanOne(app, packageName)
                recordResult(app, packageName, finding)
                markSeen(app, packageName)
            }
        }
    }

    fun onPackageRemoved(context: Context, packageName: String) {
        val app = context.applicationContext
        executor.execute {
            runCatching {
                val kept = findings(app).filterNot { it.packageName == packageName }
                val keptIgnored = ignoredFindings(app).filterNot { it.packageName == packageName }
                prefs(app).edit().putString(KEY_FINDINGS, encodeFindings(kept)).putString(KEY_IGNORED, encodeFindings(keptIgnored))
                    .remove(SEEN_PREFIX + packageName).apply()
            }
        }
    }

    /** A new signed pack was installed: apps must be checked again because the pack may know new hashes. */
    fun onPackUpdated(context: Context) {
        if (isAutoEnabled(context)) scanAll(context, force = false)
    }

    /**
     * Checks every user-installed app. Apps that did not change since the last check with the same pack are skipped
     * unless [force] is true. Returns false if a full scan was already running.
     */
    fun scanAll(
        context: Context,
        force: Boolean,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        onDone: ((List<Finding>) -> Unit)? = null
    ): Boolean {
        val app = context.applicationContext
        if (!fullScanRunning.compareAndSet(false, true)) return false
        executor.execute {
            try {
                val pm = app.packageManager
                val pack = ThreatSignatureStore.activePackVersion()
                val apps = runCatching {
                    pm.getInstalledApplications(0).filter {
                        (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 && it.packageName != app.packageName
                    }
                }.getOrDefault(emptyList())
                val p = prefs(app)
                var done = 0
                progressTotal = apps.size; progressDone = 0
                for (info in apps) {
                    done++
                    progressDone = done
                    onProgress?.invoke(done, apps.size)
                    val stamp = seenStamp(app, info.packageName, pack)
                    if (!force && p.getString(SEEN_PREFIX + info.packageName, null) == stamp) continue
                    val finding = runCatching { scanOne(app, info.packageName) }.getOrNull()
                    recordResult(app, info.packageName, finding)
                    p.edit().putString(SEEN_PREFIX + info.packageName, stamp).apply()
                }
                p.edit().putLong(KEY_LAST_FULL, System.currentTimeMillis()).putString(KEY_LAST_PACK, pack).apply()
                progressDone = 0; progressTotal = 0
                // Mark "not running" BEFORE telling the UI, so the button is enabled when it reacts.
                fullScanRunning.set(false)
                onDone?.invoke(findings(app))
            } catch (t: Throwable) {
                progressDone = 0; progressTotal = 0
                fullScanRunning.set(false)
                onDone?.invoke(findings(app))
            } finally {
                fullScanRunning.set(false)
            }
        }
        return true
    }

    /** Everything useful to research a flagged app (copy-paste friendly). Does file I/O: call off the main thread. */
    @Suppress("DEPRECATION")
    fun detailsText(context: Context, f: Finding): String {
        val pm = context.packageManager
        val sb = StringBuilder()
        sb.appendLine("Hydra Firewall ${com.hydra.firewall.BuildConfig.VERSION_NAME} — app report")
        sb.appendLine("App: ${f.label}")
        sb.appendLine("Package: ${f.packageName}")
        runCatching {
            val flags = if (android.os.Build.VERSION.SDK_INT >= 28) android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES or android.content.pm.PackageManager.GET_PERMISSIONS
            else android.content.pm.PackageManager.GET_SIGNATURES or android.content.pm.PackageManager.GET_PERMISSIONS
            val pi = pm.getPackageInfo(f.packageName, flags)
            sb.appendLine("Version: ${pi.versionName} (${if (android.os.Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()})")
            val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
            sb.appendLine("Installed: ${fmt.format(java.util.Date(pi.firstInstallTime))}  Updated: ${fmt.format(java.util.Date(pi.lastUpdateTime))}")
            val installer = if (android.os.Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(f.packageName).installingPackageName
            else pm.getInstallerPackageName(f.packageName)
            sb.appendLine("Installed by: ${installer ?: "unknown/sideloaded"}")
            val sigs = if (android.os.Build.VERSION.SDK_INT >= 28) pi.signingInfo?.apkContentsSigners else pi.signatures
            sigs.orEmpty().forEach { sb.appendLine("Signing cert SHA-256: " + AppUpdater.sha256Hex(it.toByteArray())) }
            val ai = pm.getApplicationInfo(f.packageName, 0)
            val md = java.security.MessageDigest.getInstance("SHA-256")
            java.io.File(ai.sourceDir).inputStream().use { i -> val b = ByteArray(65536); while (true) { val n = i.read(b); if (n < 0) break; md.update(b, 0, n) } }
            sb.appendLine("APK SHA-256: " + md.digest().joinToString("") { "%02x".format(it) })
            sb.appendLine("Permissions: " + pi.requestedPermissions.orEmpty().joinToString(", ") { it.removePrefix("android.permission.") })
        }
        sb.appendLine("Threat pack: ${ThreatSignatureStore.activePackVersion()}")
        sb.appendLine("Matches:")
        f.matches.forEach { m ->
            sb.appendLine("- [${m.kind}] ${m.name}${m.family?.let { " ($it)" } ?: ""} • ${m.severity} • confidence ${m.confidence} • source ${m.source}")
            if (m.detail.isNotBlank()) sb.appendLine("    ${m.detail}")
        }
        sb.appendLine(if (f.definitive) "Verdict: exact known-malware hash." else "Verdict: pattern only — may be a false positive.")
        return sb.toString()
    }

    /** Web search that helps decide whether the app is really suspicious. */
    fun googleQuery(f: Finding): String {
        val term = f.matches.firstOrNull { it.family != null }?.family ?: "malware"
        return "https://www.google.com/search?q=" + java.net.URLEncoder.encode("\"${f.packageName}\" $term", "UTF-8")
    }

    // ---- internals --------------------------------------------------------------------------------------

    private fun scanOne(context: Context, packageName: String): Finding? {
        val pm = context.packageManager
        val info = pm.getApplicationInfo(packageName, 0)
        val path = info.sourceDir ?: return null
        val file = File(path)
        if (!file.isFile || !file.canRead() || file.length() > MAX_APK_BYTES) return null
        val splits = info.splitSourceDirs?.map(::File).orEmpty().filter { it.isFile && it.canRead() }
        val matches = ThreatSignatureStore.scanApk(context, file, splits)
        if (matches.isEmpty()) return null
        val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(packageName)
        return Finding(packageName, label, matches, System.currentTimeMillis())
    }

    private fun seenStamp(context: Context, packageName: String, pack: String): String {
        val updated = runCatching { context.packageManager.getPackageInfo(packageName, 0).lastUpdateTime }.getOrDefault(0L)
        return "$updated|$pack"
    }

    private fun markSeen(context: Context, packageName: String) {
        prefs(context).edit()
            .putString(SEEN_PREFIX + packageName, seenStamp(context, packageName, ThreatSignatureStore.activePackVersion()))
            .apply()
    }

    @Synchronized
    private fun recordResult(context: Context, packageName: String, raw: Finding?) {
        // Ignored by the user (same app, same rules): keep it out of the findings and do not notify again.
        val finding = if (raw != null && isIgnored(context, raw)) null else raw
        val current = findings(context)
        val previous = current.firstOrNull { it.packageName == packageName }
        val rest = current.filterNot { it.packageName == packageName }
        val updated = if (finding == null) rest else (listOf(finding) + rest).take(MAX_FINDINGS)
        prefs(context).edit().putString(KEY_FINDINGS, encodeFindings(updated)).apply()
        if (finding != null && isNewFinding(previous, finding)) {
            val names = finding.matches.take(3).joinToString(", ") { it.name }
            SecurityEventStore.record(
                context, "APP_THREAT",
                "Known threat in ${finding.label}",
                "${finding.packageName} • $names" + if (finding.definitive) " • exact known-malware hash" else " • pattern match (may be a false positive)",
                finding.worstSeverity
            )
            NotificationHelper.notifyAppThreat(context, finding.packageName, finding.label, finding.definitive, finding.matches.first().name)
        }
    }

    /** Notify only when the app was clean before or the set of matching rules changed. */
    internal fun isNewFinding(previous: Finding?, current: Finding): Boolean =
        previous == null || previous.matches.map { it.name }.toSet() != current.matches.map { it.name }.toSet()

    internal fun encodeFindings(list: List<Finding>): String {
        val arr = JSONArray()
        for (f in list) {
            arr.put(JSONObject().apply {
                put("pkg", f.packageName); put("label", f.label); put("time", f.time)
                put("matches", JSONArray().apply {
                    f.matches.forEach { m ->
                        put(JSONObject().apply {
                            put("kind", m.kind.name); put("name", m.name); put("family", m.family ?: JSONObject.NULL)
                            put("source", m.source); put("severity", m.severity.name)
                            put("confidence", m.confidence); put("detail", m.detail)
                        })
                    }
                })
            })
        }
        return arr.toString()
    }

    internal fun decodeFindings(json: String): List<Finding> = runCatching {
        val arr = JSONArray(json)
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val ms = o.optJSONArray("matches") ?: JSONArray()
            val matches = (0 until ms.length()).mapNotNull { j ->
                val m = ms.optJSONObject(j) ?: return@mapNotNull null
                ThreatSignatureMatch(
                    kind = runCatching { ThreatSignatureMatch.Kind.valueOf(m.optString("kind")) }.getOrDefault(ThreatSignatureMatch.Kind.YARA),
                    name = m.optString("name"),
                    family = if (m.isNull("family")) null else m.optString("family"),
                    source = m.optString("source"),
                    severity = runCatching { Severity.valueOf(m.optString("severity")) }.getOrDefault(Severity.MEDIUM),
                    confidence = m.optInt("confidence"),
                    detail = m.optString("detail")
                )
            }
            if (matches.isEmpty()) null else Finding(o.optString("pkg"), o.optString("label"), matches, o.optLong("time"))
        }
    }.getOrDefault(emptyList())
}
