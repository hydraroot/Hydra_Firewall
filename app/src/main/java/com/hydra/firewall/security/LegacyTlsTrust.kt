package com.hydra.firewall.security

import android.content.Context
import java.io.InputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Compatibility trust for HTTPS update feeds on older Android devices whose
 * system CA store predates modern public roots. System trust is always tried
 * first; bundled public roots are only an additive fallback for updater URLs.
 */
object LegacyTlsTrust {
    fun configure(context: Context, connection: HttpsURLConnection) {
        connection.sslSocketFactory = sslContext(context).socketFactory
        connection.hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
        // Keep normal hostname verification.
    }

    /**
     * Optional compatibility factory for Android 7 encrypted-DNS upstreams.
     * It preserves the platform trust store and only adds the same public-root
     * compatibility certificates already bundled for HYDRA's legacy HTTPS feeds.
     */
    fun socketFactory(context: Context): javax.net.ssl.SSLSocketFactory =
        sslContext(context).socketFactory

    @Volatile
    private var cached: SSLContext? = null
    private val lock = Any()

    private fun sslContext(context: Context): SSLContext {
        cached?.let { return it }
        synchronized(lock) {
            cached?.let { return it }
            val merged = mergedTrustManager(context)
            return SSLContext.getInstance("TLS").apply {
                init(null, arrayOf<TrustManager>(merged), SecureRandom())
                cached = this
            }
        }
    }

    private fun systemTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("system_trust_manager_missing")
    }

    /**
     * Build one ordinary TrustManager containing the platform roots plus a very small
     * compatibility set for old Android TLS stacks. Using one TrustManager is more
     * compatible with Android 7 than delegating between two managers during path build.
     */
    private fun mergedTrustManager(context: Context): X509TrustManager {
        val system = systemTrustManager()
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }

        system.acceptedIssuers.forEachIndexed { index, certificate ->
            keyStore.setCertificateEntry("system-$index", certificate)
        }

        val factory = CertificateFactory.getInstance("X.509")
        context.resources.openRawResource(com.hydra.firewall.R.raw.hydra_extra_roots).use { input ->
            addCertificates(factory, input, keyStore, "hydra-extra")
        }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("merged_trust_manager_missing")
    }

    private fun addCertificates(
        factory: CertificateFactory,
        input: InputStream,
        keyStore: KeyStore,
        aliasPrefix: String
    ) {
        var index = 0
        while (true) {
            val certificate = try {
                factory.generateCertificate(input)
            } catch (_: Exception) {
                break
            }
            keyStore.setCertificateEntry("$aliasPrefix-$index", certificate)
            index++
        }
        if (index == 0) throw IllegalStateException("extra_root_missing")
    }

}
