package com.hydra.firewall.vpn

import android.content.Context
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

/**
 * Persists user-curated "known bad" JA3/JA3N hashes and keeps an in-memory,
 * bounded log of every fingerprint observed (mirrors TrafficAnalyzerStore's
 * design: metadata only, nothing payload-derived beyond the hash/SNI/ALPN).
 */
object TlsFingerprintStore {
    data class Seen(
        val id: Long,
        val timestamp: Long,
        val time: String,
        val uid: Int,
        val packageName: String?,
        val destination: String,
        val port: Int,
        val sni: String?,
        val alpn: String?,
        val ja3Hash: String,
        val ja3nHash: String,
        val hydraLiteHash: String,
        val matchedBlocklist: Boolean
    )

    private const val PREFS = "tls_fingerprint_store"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_BLOCK_ON_MATCH = "block_on_match"
    private const val KEY_KNOWN_BAD = "known_bad_hashes"
    private const val MAX_SEEN = 1000

    private val sequence = AtomicLong(0)
    private val seen = ArrayDeque<Seen>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    @Volatile private var enabled = false
    @Volatile private var blockOnMatch = false
    @Volatile private var knownBad: Set<String> = emptySet()
    private lateinit var prefs: android.content.SharedPreferences

    @Synchronized
    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        enabled = prefs.getBoolean(KEY_ENABLED, true)
        blockOnMatch = prefs.getBoolean(KEY_BLOCK_ON_MATCH, false)
        knownBad = prefs.getStringSet(KEY_KNOWN_BAD, emptySet()).orEmpty().toSet()
    }

    fun isEnabled(): Boolean = enabled
    fun setEnabled(value: Boolean) {
        enabled = value
        prefs.edit().putBoolean(KEY_ENABLED, value).apply()
        if (!value) synchronized(this) { seen.clear() }
    }

    /** When true, a JA3/JA3N match against the known-bad list resets the TCP
     *  session instead of only logging an alert. Off by default so a false
     *  positive never breaks a legitimate connection silently. */
    fun isBlockOnMatchEnabled(): Boolean = blockOnMatch
    fun setBlockOnMatch(value: Boolean) {
        blockOnMatch = value
        prefs.edit().putBoolean(KEY_BLOCK_ON_MATCH, value).apply()
    }

    fun knownBadHashes(): Set<String> = knownBad

    fun addKnownBad(hash: String, label: String? = null) {
        val h = hash.trim().lowercase(Locale.US)
        if (h.length !in 24..40) return
        val updated = knownBad + h
        knownBad = updated
        prefs.edit().putStringSet(KEY_KNOWN_BAD, updated).apply()
        if (label != null) prefs.edit().putString("label_$h", label).apply()
    }

    fun removeKnownBad(hash: String) {
        val updated = knownBad - hash
        knownBad = updated
        prefs.edit().putStringSet(KEY_KNOWN_BAD, updated).remove("label_$hash").apply()
    }

    fun labelFor(hash: String): String? = if (::prefs.isInitialized) prefs.getString("label_$hash", null) else null

    fun isKnownBad(vararg hashes: String): Boolean = hashes.any { it in knownBad }

    fun record(
        uid: Int,
        packageName: String?,
        destination: String,
        port: Int,
        result: Ja3Fingerprint.Result
    ): Seen {
        val matched = isKnownBad(result.ja3Hash, result.ja3nHash, result.hydraLiteHash)
        val event = Seen(
            id = sequence.incrementAndGet(),
            timestamp = System.currentTimeMillis(),
            time = fmt.format(Date()),
            uid = uid,
            packageName = packageName,
            destination = destination,
            port = port,
            sni = result.sni,
            alpn = result.alpn,
            ja3Hash = result.ja3Hash,
            ja3nHash = result.ja3nHash,
            hydraLiteHash = result.hydraLiteHash,
            matchedBlocklist = matched
        )
        synchronized(this) {
            seen.addLast(event)
            while (seen.size > MAX_SEEN) seen.removeFirst()
        }
        return event
    }

    @Synchronized
    fun snapshot(): List<Seen> = seen.toList().asReversed()

    @Synchronized
    fun alerts(): List<Seen> = seen.filter { it.matchedBlocklist }.asReversed()

    @Synchronized
    fun clear() = seen.clear()
}
