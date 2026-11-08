package com.hydra.firewall.security

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import com.hydra.firewall.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * Self-update from the project's signed GitHub Releases.
 *
 * Safety: the APK is only handed to Android if (1) its SHA-256 matches the one published with the release,
 * (2) it is the same package, (3) it is signed with the SAME certificate as the installed app and (4) its
 * versionCode is higher. Android itself refuses an update with a different signature, so this is a second lock.
 * Android always has the last word on installing; without "install unknown apps" for Hydra it asks the user.
 */
object AppUpdater {
    const val REPO = "hydraroot/Hydra_Firewall"
    const val ACTION_INSTALL_RESULT = "com.hydra.firewall.action.APP_UPDATE_INSTALL_RESULT"

    data class Release(
        val tag: String, val version: String, val apkUrl: String, val sizeBytes: Long,
        val sha256: String?, val sha256Url: String?, val notes: String
    )

    sealed class CheckResult {
        data class UpToDate(val current: String) : CheckResult()
        data class Available(val release: Release) : CheckResult()
        data class Error(val message: String) : CheckResult()
    }

    private const val PREFS = "hydra_app_updater"
    private const val KEY_AUTO = "auto_enabled"
    private const val KEY_LAST_CHECK = "last_check"
    private const val KEY_LAST_MSG = "last_message"
    private const val CHECK_INTERVAL_MS = 20L * 60L * 60L * 1000L
    private const val MAX_APK_BYTES = 200L * 1024L * 1024L
    /** Tope para las respuestas de texto (lista de releases y archivo .sha256). */
    private const val MAX_TEXT_BYTES = 2L * 1024L * 1024L
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "hydra-app-updater").apply { isDaemon = true } }

    private fun prefs(c: Context) = c.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun isAutoEnabled(c: Context) = prefs(c).getBoolean(KEY_AUTO, true)
    fun setAutoEnabled(c: Context, v: Boolean) { prefs(c).edit().putBoolean(KEY_AUTO, v).apply() }
    fun lastCheck(c: Context) = prefs(c).getLong(KEY_LAST_CHECK, 0L)
    fun lastMessage(c: Context): String = prefs(c).getString(KEY_LAST_MSG, "").orEmpty()
    fun setMessage(c: Context, m: String) { prefs(c).edit().putString(KEY_LAST_MSG, m).apply() }
    fun currentVersion(): String = BuildConfig.VERSION_NAME

    // ---- live progress of an update (read by the UI) ----------------------------------------------------------

    enum class Phase { IDLE, DOWNLOADING, VERIFYING, INSTALLING, CONFIRM }

    @Volatile private var phaseValue = Phase.IDLE
    @Volatile private var phaseSince = 0L
    @Volatile private var downloadedBytes = 0L
    @Volatile private var expectedBytes = 0L
    private const val STUCK_AFTER_MS = 3L * 60L * 1000L

    fun phase(): Phase {
        // Android may restart Hydra mid-install; never leave the UI stuck on a stale phase.
        if (phaseValue != Phase.IDLE && System.currentTimeMillis() - phaseSince > STUCK_AFTER_MS) phaseValue = Phase.IDLE
        return phaseValue
    }
    fun downloaded(): Long = downloadedBytes
    fun expected(): Long = expectedBytes
    internal fun setPhase(p: Phase) { phaseValue = p; phaseSince = System.currentTimeMillis() }

    /** Pure helper for the progress bar: 0f..1f, or null when the size is unknown. */
    internal fun fraction(done: Long, total: Long): Float? =
        if (total <= 0L) null else (done.toDouble() / total.toDouble()).toFloat().coerceIn(0f, 1f)

    // ---- "Hydra was just updated" (the process restarts, so the next start tells the user) --------------------

    private const val KEY_LAST_VERSION = "last_seen_version"
    private const val KEY_UPDATED_AT = "updated_at"
    private const val KEY_UPDATED_FROM = "updated_from"
    private const val RECENT_UPDATE_MS = 15L * 60L * 1000L

    /** Call once per app start: returns the previous version if Hydra was updated since the last start, else null. */
    fun consumeJustUpdated(context: Context): String? {
        val p = prefs(context)
        val previous = p.getString(KEY_LAST_VERSION, null)
        val now = currentVersion()
        p.edit().putString(KEY_LAST_VERSION, now).apply()
        if (previous.isNullOrEmpty() || previous == now) return null
        p.edit().putLong(KEY_UPDATED_AT, System.currentTimeMillis()).putString(KEY_UPDATED_FROM, previous).apply()
        return previous
    }

    /** The version Hydra was updated from, if that happened in the last few minutes (for the Security card). */
    fun recentUpdateFrom(context: Context): String? {
        val p = prefs(context)
        val at = p.getLong(KEY_UPDATED_AT, 0L)
        return if (at > 0L && System.currentTimeMillis() - at < RECENT_UPDATE_MS) p.getString(KEY_UPDATED_FROM, null) else null
    }

    // ---- version helpers (pure, unit-tested) ------------------------------------------------------------

    internal fun parseVersion(raw: String): List<Int>? {
        val m = Regex("""(?<![0-9])(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?![0-9])""").find(raw) ?: return null
        return m.groupValues.drop(1).map { it.toIntOrNull() ?: return null }
    }

    /** true if [remote] is strictly newer than [local] (both MAJOR.MINOR.PATCH, optional leading "v"). */
    internal fun isNewer(remote: String, local: String): Boolean {
        val r = parseVersion(remote) ?: return false
        val l = parseVersion(local) ?: return false
        for (i in 0..2) { if (r[i] != l[i]) return r[i] > l[i] }
        return false
    }

    internal fun parseReleases(json: String): Release? {
        val arr = JSONArray(json)
        var best: Release? = null
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            if (o.optBoolean("draft") || o.optBoolean("prerelease")) continue
            val tag = o.optString("tag_name")
            val ver = parseVersion(tag)?.joinToString(".") ?: continue
            val assets = o.optJSONArray("assets") ?: continue
            var apk: JSONObject? = null
            var sha: JSONObject? = null
            for (j in 0 until assets.length()) {
                val a = assets.optJSONObject(j) ?: continue
                val name = a.optString("name")
                if (name.endsWith(".apk", true)) apk = a
                if (name.endsWith(".apk.sha256", true)) sha = a
            }
            val apkObj = apk ?: continue
            val url = apkObj.optString("browser_download_url")
            if (!url.startsWith("https://")) continue
            val digest = apkObj.optString("digest").removePrefix("sha256:").lowercase().takeIf { it.length == 64 }
            val cand = Release(tag, ver, url, apkObj.optLong("size"), digest, sha?.optString("browser_download_url"), o.optString("body"))
            if (best == null || isNewer(cand.version, best.version)) best = cand
        }
        return best
    }

    // ---- check / download / install ---------------------------------------------------------------------

    fun check(context: Context, callback: (CheckResult) -> Unit) {
        val app = context.applicationContext
        executor.execute {
            val result = runCatching {
                val json = httpText(app, "https://api.github.com/repos/$REPO/releases?per_page=10")
                val rel = parseReleases(json)
                prefs(app).edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply()
                if (rel != null && isNewer(rel.version, currentVersion())) CheckResult.Available(rel)
                else CheckResult.UpToDate(currentVersion())
            }.getOrElse { CheckResult.Error(it.message ?: it.javaClass.simpleName) }
            setMessage(app, when (result) {
                is CheckResult.UpToDate -> "UP_TO_DATE"
                is CheckResult.Available -> "AVAILABLE:" + result.release.version
                is CheckResult.Error -> "ERROR:" + result.message
            })
            callback(result)
        }
    }

    /** Called by the daily alarm and when the app opens. Downloads on unmetered networks only. */
    fun autoCheck(context: Context) {
        val app = context.applicationContext
        if (!isAutoEnabled(app)) return
        if (System.currentTimeMillis() - lastCheck(app) < CHECK_INTERVAL_MS) return
        check(app) { r ->
            if (r is CheckResult.Available) {
                // A debug/test build has a different signature: a release APK can never replace it, so do not download.
                if (isMetered(app) || isDebugBuild(app)) {
                    com.hydra.firewall.vpn.NotificationHelper.notifyAppUpdate(app, r.release.version, readyToInstall = false)
                } else {
                    downloadAndInstall(app, r.release, background = true) { }
                }
            }
        }
    }

    fun downloadAndInstall(context: Context, release: Release, background: Boolean, onDone: (String?) -> Unit) {
        val app = context.applicationContext
        executor.execute {
            downloadedBytes = 0L; expectedBytes = release.sizeBytes
            setPhase(Phase.DOWNLOADING)
            val error = runCatching {
                val dir = File(app.cacheDir, "update").apply { mkdirs(); listFiles()?.forEach { it.delete() } }
                val file = File(dir, "Hydra-Firewall-${release.version}.apk")
                val actual = download(app, release.apkUrl, file)
                setPhase(Phase.VERIFYING)
                val expected = release.sha256
                    ?: release.sha256Url?.let { httpText(app, it).trim().split(Regex("\\s+")).firstOrNull()?.lowercase() }
                require(expected != null && expected.length == 64) { "no_published_sha256" }
                require(actual == expected) { "sha256_mismatch" }
                verifyPackage(app, file)
                commitInstall(app, file, background, release.version)
                null
            }.getOrElse { it.message ?: it.javaClass.simpleName }
            if (error != null) { setMessage(app, "ERROR:$error"); setPhase(Phase.IDLE) }
            onDone(error)
        }
    }

    private fun verifyPackage(context: Context, file: File) {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val archive = pm.getPackageArchiveInfo(file.absolutePath, flags) ?: error("not_an_apk")
        require(archive.packageName == context.packageName) { "wrong_package" }
        val own = pm.getPackageInfo(context.packageName, flags)
        val newCode = if (Build.VERSION.SDK_INT >= 28) archive.longVersionCode else @Suppress("DEPRECATION") archive.versionCode.toLong()
        val oldCode = if (Build.VERSION.SDK_INT >= 28) own.longVersionCode else @Suppress("DEPRECATION") own.versionCode.toLong()
        require(newCode > oldCode) { "not_newer:$newCode:$oldCode" }
        val newCerts = certs(archive)
        val ownCerts = certs(own)
        // If Android cannot read the signature of a file that is not installed yet (it happens on some devices) we do
        // not block: the installer itself refuses an APK signed with a different key, so that is the real lock.
        // Desde API 28 Android SÍ expone la firma de un APK no instalado: si viene vacía es un archivo anómalo.
        require(!(Build.VERSION.SDK_INT >= 28 && newCerts.isEmpty())) { "unreadable_signature" }
        require(signaturesCompatible(ownCerts, newCerts)) {
            "signature_differs (${ownCerts.firstOrNull()?.take(12) ?: "?"} → ${newCerts.firstOrNull()?.take(12) ?: "?"})"
        }
    }

    /** Pure rule: unreadable new signature = let Android decide; otherwise the sets must share a certificate. */
    internal fun signaturesCompatible(own: Set<String>, new: Set<String>): Boolean =
        new.isEmpty() || own.isEmpty().not() && own.intersect(new).isNotEmpty()

    @Suppress("DEPRECATION")
    private fun certs(info: android.content.pm.PackageInfo): Set<String> {
        val sigs = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        return sigs.orEmpty().map { sha256Hex(it.toByteArray()) }.toSet()
    }

    private fun commitInstall(context: Context, file: File, background: Boolean, version: String) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(context.packageName)
        if (Build.VERSION.SDK_INT >= 31) params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        val id = installer.createSession(params)
        try {
            installer.openSession(id).use { session ->
                file.inputStream().use { input ->
                    session.openWrite("hydra.apk", 0, file.length()).use { out ->
                        input.copyTo(out); session.fsync(out)
                    }
                }
                val intent = Intent(context, UpdateInstallReceiver::class.java).setAction(ACTION_INSTALL_RESULT)
                    .putExtra("version", version).putExtra("background", background)
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                session.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
            }
        } catch (t: Throwable) {
            // No dejar sesiones huérfanas si la escritura o el commit fallan.
            runCatching { installer.abandonSession(id) }
            throw t
        }
        setPhase(Phase.INSTALLING)
        setMessage(context, "INSTALLING:$version")
    }

    // ---- network ----------------------------------------------------------------------------------------

    private fun isMetered(context: Context): Boolean =
        (context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).isActiveNetworkMetered

    private fun open(context: Context, url: String): HttpURLConnection {
        require(url.startsWith("https://")) { "https_required" }
        var conn: HttpURLConnection? = null
        for (n in ThreatSignatureUpdater.physicalNetworks(context)) {
            conn = runCatching { n.openConnection(URL(url)) as HttpURLConnection }.getOrNull()
            if (conn != null) break
        }
        val c = conn ?: (URL(url).openConnection() as HttpURLConnection)
        c.connectTimeout = 15_000; c.readTimeout = 30_000; c.instanceFollowRedirects = true; c.useCaches = false
        c.setRequestProperty("User-Agent", "Hydra-Firewall/${BuildConfig.VERSION_NAME}")
        c.setRequestProperty("Accept", "application/vnd.github+json, application/octet-stream, */*")
        return c
    }

    private fun httpText(context: Context, url: String): String {
        val c = open(context, url)
        try {
            if (c.responseCode !in 200..299) error("http_${c.responseCode}")
            if (c.contentLengthLong > MAX_TEXT_BYTES) error("text_too_large")
            val out = java.io.ByteArrayOutputStream()
            c.inputStream.use { input ->
                val buf = ByteArray(8 * 1024)
                while (true) {
                    val n = input.read(buf); if (n < 0) break
                    if (out.size() + n > MAX_TEXT_BYTES) error("text_too_large")
                    out.write(buf, 0, n)
                }
            }
            return out.toString(Charsets.UTF_8.name())
        } finally { c.disconnect() }
    }

    private fun download(context: Context, url: String, dest: File): String {
        val c = open(context, url)
        try {
            if (c.responseCode !in 200..299) error("http_${c.responseCode}")
            if (!c.url.protocol.equals("https", true)) error("downgraded_to_http")
            if (c.contentLengthLong > MAX_APK_BYTES) error("apk_too_large")
            if (c.contentLengthLong > 0L) expectedBytes = c.contentLengthLong
            val md = MessageDigest.getInstance("SHA-256")
            var total = 0L
            c.inputStream.use { input -> dest.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf); if (n < 0) break
                    total += n; if (total > MAX_APK_BYTES) error("apk_too_large")
                    downloadedBytes = total
                    md.update(buf, 0, n); out.write(buf, 0, n)
                }
            } }
            return md.digest().joinToString("") { "%02x".format(it) }
        } finally { c.disconnect() }
    }

    /** First 12 hex chars of the installed app's signing-certificate SHA-256 (to compare with the release key). */
    fun ownCertShort(context: Context): String = runCatching {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        certs(context.packageManager.getPackageInfo(context.packageName, flags)).firstOrNull()?.take(12)
    }.getOrNull() ?: "?"

    /** SHA-256 of the signing certificate(s) of an installed package (sorted, comma-joined), or null. */
    internal fun signerSha(context: Context, packageName: String): String? = runCatching {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        certs(context.packageManager.getPackageInfo(packageName, flags)).sorted().joinToString(",")
    }.getOrNull()?.takeIf { it.isNotEmpty() }

    /** True if this install is a debug/test build (those can never be updated by the release APK). */
    fun isDebugBuild(context: Context): Boolean =
        (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

    internal fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
