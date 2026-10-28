package com.hydra.firewall.security

import android.content.Context
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference

/**
 * Live threat-intelligence domain set derived from the dedicated threat-only
 * blocklist source (currently HaGeZi TIF mini). This is kept separate from
 * generic ad/tracker domains so the Security Engine can classify and notify
 * high/critical threat matches without treating ordinary advertising as malware.
 *
 * The file is protected by a SHA-256 sidecar and replaced atomically. The source
 * itself is obtained over validated HTTPS by BlocklistUpdater; the sidecar protects
 * against local corruption, not against a compromised upstream source.
 */
object ThreatIntelDomainStore {
    private const val FILE_NAME = "hydra_live_threat_domains.txt"
    private const val META_NAME = "hydra_live_threat_domains.sha256"
    private const val PREFS = "hydra_live_threat_domains"
    private const val KEY_SOURCE = "source"
    private const val KEY_DATE = "date"
    private const val MIN_DOMAINS = 100
    private const val MAX_DOMAINS = 200_000

    data class Info(val count: Int, val source: String, val date: String)

    private val domains = AtomicReference<Set<String>>(emptySet())
    private val info = AtomicReference(Info(0, "", ""))
    @Volatile private var initialized = false
    @Volatile private var appContext: Context? = null

    @Synchronized
    fun init(context: Context) {
        appContext = context.applicationContext
        if (initialized) return
        initialized = true
        load()
    }

    @Synchronized
    fun install(context: Context, values: Collection<String>, source: String, date: String): Boolean {
        init(context)
        val cleaned = values.asSequence()
            .map(::normalize)
            .filter { it.isNotBlank() }
            .distinct()
            .take(MAX_DOMAINS + 1)
            .toList()
        if (cleaned.size < MIN_DOMAINS || cleaned.size > MAX_DOMAINS) return false

        val ctx = context.applicationContext
        val target = File(ctx.filesDir, FILE_NAME)
        val meta = File(ctx.filesDir, META_NAME)
        val tmp = File(ctx.filesDir, "$FILE_NAME.tmp")
        val tmpMeta = File(ctx.filesDir, "$META_NAME.tmp")
        return runCatching {
            tmp.bufferedWriter(Charsets.UTF_8).use { w ->
                for (d in cleaned) {
                    w.write(d)
                    w.newLine()
                }
            }
            val digest = sha256(tmp)
            tmpMeta.writeText(digest, Charsets.US_ASCII)
            if (!tmp.renameTo(target)) {
                tmp.copyTo(target, overwrite = true)
                tmp.delete()
            }
            if (!tmpMeta.renameTo(meta)) {
                tmpMeta.copyTo(meta, overwrite = true)
                tmpMeta.delete()
            }
            // Re-read and verify the exact bytes we activated.
            require(sha256(target).equals(digest, ignoreCase = true))
            domains.set(cleaned.toHashSet())
            info.set(Info(cleaned.size, source.take(240), date.take(240)))
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_SOURCE, source.take(240))
                .putString(KEY_DATE, date.take(240))
                .apply()
            true
        }.getOrElse {
            runCatching { tmp.delete() }
            runCatching { tmpMeta.delete() }
            false
        }
    }

    fun match(domain: String): Boolean {
        if (!initialized) appContext?.let { init(it) } else Unit
        val normalized = normalize(domain)
        if (normalized.isBlank()) return false
        var current = normalized
        val set = domains.get()
        while (true) {
            if (set.contains(current)) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
            if (current.isBlank() || !current.contains('.')) return false
        }
    }

    fun info(context: Context): Info {
        init(context)
        return info.get()
    }

    private fun load() {
        val ctx = appContext ?: return
        val target = File(ctx.filesDir, FILE_NAME)
        val meta = File(ctx.filesDir, META_NAME)
        if (!target.isFile || !meta.isFile) return
        val expected = runCatching { meta.readText(Charsets.US_ASCII).trim() }.getOrNull().orEmpty()
        if (expected.isBlank() || !sha256(target).equals(expected, ignoreCase = true)) return
        val set = runCatching {
            target.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.map(::normalize).filter { it.isNotBlank() }.take(MAX_DOMAINS + 1).toSet()
            }
        }.getOrNull() ?: return
        if (set.size !in MIN_DOMAINS..MAX_DOMAINS) return
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        info.set(Info(set.size, prefs.getString(KEY_SOURCE, "") ?: "", prefs.getString(KEY_DATE, "") ?: ""))
        domains.set(set)
    }

    private fun normalize(value: String): String = value.trim().trimEnd('.').lowercase(Locale.US).removePrefix(".")

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
