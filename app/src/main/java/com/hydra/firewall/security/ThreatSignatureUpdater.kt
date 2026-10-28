package com.hydra.firewall.security

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Downloads a Hydra-signed threat pack. Third-party feeds are never trusted
 * directly by the application; a signed Hydra pack must be produced first.
 * This avoids shipping a ThreatFox/URLhaus API key in every APK.
 */
object ThreatSignatureUpdater {
    private const val TAG = "ThreatSignatureUpdater"
    private const val CONNECT_TIMEOUT_MS = 12_000
    private const val READ_TIMEOUT_MS = 30_000
    private const val PREFS = "hydra_threat_signatures"
    private const val KEY_FEED_URL = "feed_url"
    private const val DEFAULT_INTERVAL_MS = 24L * 60L * 60L * 1000L
    private val executor = Executors.newSingleThreadExecutor()

    data class Result(val success: Boolean, val version: String? = null, val error: String? = null, val skipped: Boolean = false)

    /** URL elegida por el usuario; si no hay, la URL por defecto compilada (HYDRA_THREAT_FEED_URL). */
    fun configuredFeedUrl(context: Context): String {
        val custom = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_FEED_URL, "")?.trim().orEmpty()
        return custom.ifBlank { com.hydra.firewall.BuildConfig.THREAT_FEED_URL.trim() }
    }

    fun setFeedUrl(context: Context, url: String) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_FEED_URL, url.trim()).apply()
    }

    fun updateIfDue(context: Context, force: Boolean = false, callback: ((Result) -> Unit)? = null) {
        executor.execute {
            val result = runCatching {
                val url = configuredFeedUrl(context)
                if (url.isBlank()) return@runCatching Result(true, ThreatSignatureStore.activePackVersion(), skipped = true)
                val last = ThreatSignatureStore.lastUpdate(context)
                if (!force && last > 0L && System.currentTimeMillis() - last < DEFAULT_INTERVAL_MS) {
                    return@runCatching Result(true, ThreatSignatureStore.activePackVersion(), skipped = true)
                }
                if (!url.startsWith("https://")) throw IllegalArgumentException("feed_requires_https")
                val payload = download(context.applicationContext, url)
                if (!ThreatSignatureVerifier.verifyAndExtract(payload).isNullOrBlank()) {
                    if (!ThreatSignatureStore.installVerifiedPack(context, payload)) {
                        throw IllegalStateException("pack_install_failed")
                    }
                    Result(true, ThreatSignatureStore.activePackVersion())
                } else {
                    throw IllegalStateException("signature_invalid")
                }
            }.getOrElse { e ->
                Log.w(TAG, "Threat update failed", e)
                ThreatSignatureStore.markUpdateError(context, e.message ?: e.javaClass.simpleName)
                Result(false, error = e.message ?: e.javaClass.simpleName)
            }
            callback?.invoke(result)
        }
    }

    fun scheduleDaily(context: Context) {
        val alarm = context.applicationContext.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, com.hydra.firewall.vpn.BootReceiver::class.java).apply {
            action = com.hydra.firewall.vpn.BootReceiver.ACTION_THREAT_UPDATE
        }
        val pending = PendingIntent.getBroadcast(
            context, 9451, intent,
            if (android.os.Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE else PendingIntent.FLAG_UPDATE_CURRENT
        )
        val trigger = System.currentTimeMillis() + 30L * 60L * 1000L
        alarm.setInexactRepeating(AlarmManager.RTC_WAKEUP, trigger, DEFAULT_INTERVAL_MS, pending)
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

    private fun download(context: Context, rawUrl: String): String {
        var lastError: Throwable? = null

        fun attempt(opener: () -> HttpURLConnection): String {
            val conn = opener().apply {
                if (this is HttpsURLConnection) {
                    LegacyTlsTrust.configure(context.applicationContext, this)
                }
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                requestMethod = "GET"
                instanceFollowRedirects = true
                useCaches = false
                setRequestProperty("User-Agent", "Hydra-Firewall/${com.hydra.firewall.BuildConfig.VERSION_NAME}")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("Accept-Encoding", "identity")
                setRequestProperty("Cache-Control", "no-cache")
            }
            try {
                val code = conn.responseCode
                if (code !in 200..299) throw IllegalStateException("http_$code")
                if (!conn.url.protocol.equals("https", ignoreCase = true)) throw IllegalStateException("feed_downgraded_to_http")
                val declared = conn.contentLengthLong
                if (declared > 20L * 1024L * 1024L) throw IllegalStateException("pack_too_large")

                val out = ByteArrayOutputStream(if (declared in 1..(20L * 1024L * 1024L)) declared.toInt() else 64 * 1024)
                val buffer = ByteArray(32 * 1024)
                var total = 0L
                conn.inputStream.use { input ->
                    while (true) {
                        val n = input.read(buffer)
                        if (n <= 0) break
                        total += n
                        if (total > 20L * 1024L * 1024L) throw IllegalStateException("pack_too_large")
                        out.write(buffer, 0, n)
                    }
                }
                return out.toString(StandardCharsets.UTF_8.name())
            } finally {
                conn.disconnect()
            }
        }

        for (network in physicalNetworks(context)) {
            try {
                return attempt { network.openConnection(URL(rawUrl)) as HttpURLConnection }
            } catch (t: Throwable) {
                lastError = t
                Log.w(TAG, "Physical-network threat feed failed", t)
            }
        }

        try {
            return attempt { URL(rawUrl).openConnection() as HttpURLConnection }
        } catch (t: Throwable) {
            lastError = t
        }
        throw lastError ?: IllegalStateException("no_threat_feed_network")
    }

}
