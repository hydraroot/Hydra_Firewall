package com.hydra.firewall.security

import android.content.Context
import android.net.Network
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Opens updater HTTP connections only on an explicitly selected physical network.
 *
 * Do not add a URL.openConnection() fallback here: while Hydra's VPN is active,
 * the process default network may be the VPN itself. A failed physical-network
 * attempt must fail closed instead of routing the updater through the tunnel.
 */
internal object PhysicalNetworkHttp {
    const val MAX_REDIRECTS = 3

    private val redirectCodes = setOf(301, 302, 303, 307, 308)

    fun open(
        context: Context,
        rawUrl: String,
        configure: (HttpsURLConnection) -> Unit
    ): HttpsURLConnection {
        val initial = validateInitialHttpsUrl(rawUrl)

        val networks = ThreatSignatureUpdater.physicalNetworks(context)
        if (networks.isEmpty()) throw IllegalStateException("no_physical_network")

        var lastError: Exception? = null
        for (network in networks) {
            try {
                return openOnNetwork(network, initial, configure)
            } catch (t: Exception) {
                lastError = t
            }
        }
        throw lastError ?: IllegalStateException("no_physical_network")
    }

    private fun openOnNetwork(
        network: Network,
        initial: URL,
        configure: (HttpsURLConnection) -> Unit
    ): HttpsURLConnection {
        var current = initial
        var redirects = 0
        val visited = HashSet<String>()

        while (true) {
            if (!visited.add(current.toExternalForm())) {
                throw IllegalStateException("redirect_loop")
            }

            val connection = network.openConnection(current) as? HttpsURLConnection
                ?: throw IllegalStateException("https_connection_required")

            try {
                configure(connection)
                // Redirects are handled here so every hop remains attached to this Network.
                connection.instanceFollowRedirects = false
                val code = connection.responseCode
                if (code !in redirectCodes) return connection

                val next = resolveHttpsRedirect(current, connection.getHeaderField("Location"))
                if (redirects >= MAX_REDIRECTS) {
                    throw IllegalStateException("too_many_redirects")
                }
                connection.disconnect()
                current = next
                redirects++
            } catch (t: Exception) {
                connection.disconnect()
                throw t
            }
        }
    }

    /** Pure initial URL policy, exposed internally so the URL rules can be unit-tested. */
    internal fun validateInitialHttpsUrl(rawUrl: String): URL {
        val initial = URL(rawUrl)
        require(
            initial.protocol.equals("https", ignoreCase = true) &&
                initial.host.isNotBlank() && initial.userInfo == null
        ) { "https_required" }
        return initial
    }

    /** Pure redirect policy, exposed internally so the URL rules can be unit-tested. */
    internal fun resolveHttpsRedirect(base: URL, location: String?): URL {
        require(!location.isNullOrBlank()) { "redirect_location_missing" }
        val next = URL(base, location.trim())
        require(
            next.protocol.equals("https", ignoreCase = true) &&
                next.host.isNotBlank() && next.userInfo == null
        ) { "redirect_not_https" }
        return next
    }
}
