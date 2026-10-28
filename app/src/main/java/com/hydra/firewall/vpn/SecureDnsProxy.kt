package com.hydra.firewall.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import com.hydra.firewall.security.LegacyTlsTrust
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Encrypted DNS resolver used inside Hydra's local VPN.
 *
 * DoT is retained as the default transport. DoH uses HTTPS POST with the
 * application/dns-message media type and is opened on a physical Android
 * Network so Hydra does not loop its own upstream DNS traffic back through
 * the VPN tunnel.
 */
class SecureDnsProxy(private val service: VpnService) {
    companion object {
        private const val CONNECT_TIMEOUT_MS = 5000
        private const val READ_TIMEOUT_MS = 7000
        private const val MAX_RESPONSE = 65535
    }

    private val ruleStore = RuleStore(service)
    private val executor = Executors.newFixedThreadPool(2)

    fun query(query: ByteArray, callback: (ByteArray?) -> Unit) {
        if (query.isEmpty()) { callback(null); return }
        executor.execute {
            val response = try {
                val config = ruleStore.activeDnsProviderConfig()
                validateProviderConfiguration(config)
                try {
                    when (ruleStore.dnsTransport) {
                        DnsTransport.DOT -> queryDoT(config, query)
                        DnsTransport.DOH -> queryDoH(config, query)
                    }
                } catch (primary: Exception) {
                    val fallback = when (ruleStore.dnsTransport) {
                        DnsTransport.DOT -> config.dohUrl
                            ?.takeIf { it.startsWith("https://", ignoreCase = true) }
                            ?.let { runCatching { queryDoH(config, query) }.getOrNull() }
                        DnsTransport.DOH -> if (config.ipv4.isNotEmpty() || config.ipv6.isNotEmpty()) {
                            runCatching { queryDoT(config, query) }.getOrNull()
                        } else null
                    }
                    if (fallback != null) {
                        DiagnosticLogger.logServiceEvent(
                            "SECURE_DNS FALLBACK primary=${ruleStore.dnsTransport.name} error=${primary.javaClass.simpleName}:${primary.message ?: ""}"
                        )
                        fallback
                    } else {
                        DiagnosticLogger.logServiceEvent(
                            "SECURE_DNS FAILED transport=${ruleStore.dnsTransport.name} error=${primary.javaClass.simpleName}:${primary.message ?: ""}"
                        )
                        null
                    }
                }
            } catch (e: Exception) {
                DiagnosticLogger.logServiceEvent(
                    "SECURE_DNS FAILED setup error=${e.javaClass.simpleName}:${e.message ?: ""}"
                )
                null
            }
            callback(response)
        }
    }

    private fun validateProviderConfiguration(config: DnsProviderConfig) {
        val securityIps = setOf("1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002")
        if (config.ipv4.any(securityIps::contains) || config.ipv6.any(securityIps::contains)) {
            if (config.tlsHostname != "security.cloudflare-dns.com" ||
                config.dohUrl != "https://security.cloudflare-dns.com/dns-query") {
                throw IllegalStateException("cloudflare_security_provider_hostname_mismatch")
            }
        }
    }

    private fun queryDoT(config: DnsProviderConfig, query: ByteArray): ByteArray {
        val addresses = config.ipv4 + config.ipv6
        if (addresses.isEmpty()) throw IllegalStateException("No encrypted DNS endpoint configured")
        var last: Exception? = null
        for (ip in addresses) {
            try {
                return queryDoTEndpoint(ip, config.tlsHostname, query)
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("No DoT endpoint")
    }

    private fun queryDoTEndpoint(ip: String, tlsHostname: String, query: ByteArray): ByteArray {
        val raw = openProtectedPhysicalSocket(ip, 853)
        try {
            raw.soTimeout = READ_TIMEOUT_MS
            DiagnosticLogger.logServiceEvent("SECURE_DNS DOT_CONNECTED ip=$ip host=$tlsHostname")
            val factory = LegacyTlsTrust.socketFactory(service)
            val ssl = factory.createSocket(raw, tlsHostname, 853, true) as SSLSocket
            try {
                val params = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                if (android.os.Build.VERSION.SDK_INT >= 24) {
                    params.serverNames = listOf(javax.net.ssl.SNIHostName(tlsHostname))
                }
                // Android 7: keep encrypted DNS on the modern TLS version that
                // the provider supports, avoiding legacy protocol negotiation.
                runCatching { params.protocols = arrayOf("TLSv1.2") }
                ssl.sslParameters = params
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOT_HANDSHAKE_BEGIN ip=$ip host=$tlsHostname")
                ssl.startHandshake()
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOT_HANDSHAKE_OK ip=$ip host=$tlsHostname")

                val out = DataOutputStream(ssl.outputStream)
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOT_QUERY_SENT ip=$ip bytes=${query.size}")

                val input = DataInputStream(ssl.inputStream)
                val len = input.readUnsignedShort()
                if (len <= 0 || len > MAX_RESPONSE) throw IllegalStateException("Invalid DoT response length=$len")
                val response = ByteArray(len)
                input.readFully(response)
                if (!DnsMessageValidator.isResponse(response)) throw IllegalStateException("Malformed DoT response")
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOT_RESPONSE_OK ip=$ip bytes=${response.size}")
                return response
            } finally {
                runCatching { ssl.close() }
            }
        } finally {
            runCatching { raw.close() }
        }
    }

    private fun queryDoH(config: DnsProviderConfig, query: ByteArray): ByteArray {
        val endpoint = config.dohUrl ?: throw IllegalStateException("provider_doh_not_available")
        val url = URL(endpoint)
        val host = url.host
        val path = buildString {
            append(if (url.path.isNullOrEmpty()) "/dns-query" else url.path)
            if (!url.query.isNullOrEmpty()) {
                append('?')
                append(url.query)
            }
        }

        // Prefer a raw TLS connection to the provider's configured numeric IPs.
        // This avoids depending on the device hostname resolver while HYDRA is
        // itself intercepting DNS, and keeps the upstream connection outside the
        // VPN via VpnService.protect(). HTTPS/443 is used because it is generally
        // reachable on networks where DoT/853 is filtered.
        var lastError: Throwable? = null
        val ips = (config.ipv4 + config.ipv6).distinct()
        for (ip in ips) {
            try {
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_TRY ip=$ip host=$host")
                return queryDoHIpEndpoint(ip, host, path, query)
            } catch (t: Throwable) {
                lastError = t
                DiagnosticLogger.logServiceEvent(
                    "SECURE_DNS DOH_IP_FAILED ip=$ip error=${t.javaClass.simpleName}:${t.message ?: ""}"
                )
            }
        }

        // Keep the Android Network-bound implementation as a secondary fallback
        // for providers/custom configurations whose numeric endpoint is not usable.
        for (network in physicalNetworks()) {
            try {
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_NETWORK_TRY host=$host network=$network")
                return queryDoHEndpoint(network, endpoint, query)
            } catch (t: Throwable) {
                lastError = t
                DiagnosticLogger.logServiceEvent(
                    "SECURE_DNS DOH_NETWORK_FAILED error=${t.javaClass.simpleName}:${t.message ?: ""}"
                )
            }
        }

        try {
            return queryDoHEndpoint(null, endpoint, query)
        } catch (t: Throwable) {
            lastError = t
        }
        throw lastError ?: IllegalStateException("No DoH endpoint")
    }

    private fun queryDoHIpEndpoint(ip: String, host: String, path: String, query: ByteArray): ByteArray {
        val raw = openProtectedPhysicalSocket(ip, 443)
        try {
            raw.soTimeout = READ_TIMEOUT_MS
            DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_CONNECTED ip=$ip host=$host")

            val factory = LegacyTlsTrust.socketFactory(service)
            val ssl = factory.createSocket(raw, host, 443, true) as SSLSocket
            try {
                val params = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                if (android.os.Build.VERSION.SDK_INT >= 24) {
                    params.serverNames = listOf(javax.net.ssl.SNIHostName(host))
                }
                // Android 7 devices can have providers where the negotiated
                // protocol set is broader than necessary. Keep DoH on TLS 1.2.
                runCatching { params.protocols = arrayOf("TLSv1.2") }
                ssl.sslParameters = params
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_HANDSHAKE_BEGIN ip=$ip host=$host")
                ssl.startHandshake()
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_HANDSHAKE_OK ip=$ip host=$host")

                val target = if (path.startsWith('/')) path else "/$path"
                val requestHeaders = buildString {
                    append("POST ").append(target).append(" HTTP/1.1\r\n")
                    append("Host: ").append(host).append("\r\n")
                    append("Content-Type: application/dns-message\r\n")
                    append("Accept: application/dns-message\r\n")
                    append("Content-Length: ").append(query.size).append("\r\n")
                    append("Connection: close\r\n")
                    append("User-Agent: Hydra-Firewall/").append(com.hydra.firewall.BuildConfig.VERSION_NAME).append("\r\n")
                    append("\r\n")
                }.toByteArray(Charsets.ISO_8859_1)

                val out = ssl.outputStream
                out.write(requestHeaders)
                out.write(query)
                out.flush()
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_QUERY_SENT ip=$ip bytes=${query.size}")

                val input = ssl.inputStream
                val headerBytes = ByteArrayOutputStream(1024)
                var matched = 0
                while (headerBytes.size() < 32 * 1024) {
                    val b = input.read()
                    if (b < 0) throw java.io.EOFException("DoH headers ended early")
                    headerBytes.write(b)
                    matched = when {
                        matched == 0 && b == '\r'.code -> 1
                        matched == 1 && b == '\n'.code -> 2
                        matched == 2 && b == '\r'.code -> 3
                        matched == 3 && b == '\n'.code -> 4
                        else -> if (b == '\r'.code) 1 else 0
                    }
                    if (matched == 4) break
                }
                if (matched != 4) throw IllegalStateException("Invalid DoH HTTP headers")

                val headerText = headerBytes.toByteArray().toString(Charsets.ISO_8859_1)
                val statusLine = headerText.lineSequence().firstOrNull()?.trim().orEmpty()
                val statusCode = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: -1
                if (statusCode !in 200..299) throw IllegalStateException("doh_http_$statusCode")

                val response = readHttpBody(input, headerText)
                if (!DnsMessageValidator.isResponse(response)) throw IllegalStateException("Malformed DoH response")
                DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_IP_OK ip=$ip bytes=${response.size}")
                return response
            } finally {
                runCatching { ssl.close() }
            }
        } finally {
            runCatching { raw.close() }
        }
    }

    private fun queryDoHEndpoint(network: Network?, endpoint: String, query: ByteArray): ByteArray {
        val raw = if (network != null) network.openConnection(URL(endpoint)) else URL(endpoint).openConnection()
        val conn = raw as? HttpsURLConnection ?: throw IllegalStateException("doh_requires_https")
        try {
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.useCaches = false
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Content-Type", "application/dns-message")
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.setRequestProperty("Cache-Control", "no-cache")
            conn.setRequestProperty("User-Agent", "Hydra-Firewall/${com.hydra.firewall.BuildConfig.VERSION_NAME}")
            conn.outputStream.use { output -> output.write(query) }
            DiagnosticLogger.logServiceEvent("SECURE_DNS DOH_NETWORK_QUERY_SENT endpoint=$endpoint bytes=${query.size}")
            val code = conn.responseCode
            if (code !in 200..299) throw IllegalStateException("doh_http_$code")
            val length = conn.contentLengthLong
            if (length > MAX_RESPONSE) throw IllegalStateException("doh_response_too_large")
            val response = conn.inputStream.use { input ->
                val buffer = ByteArray(MAX_RESPONSE)
                var total = 0
                while (true) {
                    val n = input.read(buffer, total, buffer.size - total)
                    if (n < 0) break
                    if (n == 0) continue
                    total += n
                    if (total == buffer.size) break
                }
                buffer.copyOf(total)
            }
            if (!DnsMessageValidator.isResponse(response)) throw IllegalStateException("Malformed DoH response")
            return response
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Opens an upstream socket on a real physical Android Network and also
     * marks it protected from the VPN. Binding to a physical Network matters
     * on Android 7: protect() alone can still leave routing tied to the
     * application's default network while the VPN is the process default.
     */
    private fun openProtectedPhysicalSocket(ip: String, port: Int): Socket {
        var last: Throwable? = null
        val networks = physicalNetworks()
        for (network in networks) {
            try {
                val socket = network.socketFactory.createSocket()
                // Network.bindSocket() is a Unit-returning API on Android;
                // failure is reported by throwing an exception.
                network.bindSocket(socket)
                if (!service.protect(socket)) {
                    runCatching { socket.close() }
                    throw IllegalStateException("protect() failed")
                }
                DiagnosticLogger.logServiceEvent("SECURE_DNS UPSTREAM_NETWORK network=$network ip=$ip port=$port")
                socket.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)
                return socket
            } catch (t: Throwable) {
                last = t
                DiagnosticLogger.logServiceEvent(
                    "SECURE_DNS UPSTREAM_NETWORK_FAILED ip=$ip port=$port error=${t.javaClass.simpleName}:${t.message ?: ""}"
                )
            }
        }
        throw last ?: IllegalStateException("no_physical_network_available")
    }

    /** Read a DoH HTTP/1.1 body without waiting for EOF when the server sends
     * Content-Length. Chunked transfer is also accepted. */
    private fun readHttpBody(input: java.io.InputStream, headerText: String): ByteArray {
        val headers = headerText.lineSequence()
            .drop(1)
            .mapNotNull {
                val idx = it.indexOf(':')
                if (idx <= 0) null else it.substring(0, idx).trim().lowercase() to it.substring(idx + 1).trim()
            }
            .toMap()
        val contentLength = headers["content-length"]?.toLongOrNull()
        if (contentLength != null) {
            if (contentLength < 0 || contentLength > MAX_RESPONSE) throw IllegalStateException("doh_response_too_large")
            val body = ByteArray(contentLength.toInt())
            var offset = 0
            while (offset < body.size) {
                val n = input.read(body, offset, body.size - offset)
                if (n < 0) throw java.io.EOFException("DoH body ended early")
                if (n == 0) continue
                offset += n
            }
            return body
        }
        if (headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true) {
            return readChunkedBody(input)
        }
        // Last resort for HTTP/1.0 or a server that closes the connection.
        val body = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (n == 0) continue
            if (body.size() + n > MAX_RESPONSE) throw IllegalStateException("doh_response_too_large")
            body.write(buf, 0, n)
        }
        return body.toByteArray()
    }

    private fun readChunkedBody(input: java.io.InputStream): ByteArray {
        val body = ByteArrayOutputStream()
        while (true) {
            val line = readAsciiLine(input, 8192) ?: throw java.io.EOFException("chunk_size_missing")
            val sizeText = line.substringBefore(';').trim()
            val size = sizeText.toLongOrNull(16) ?: throw IllegalStateException("invalid_chunk_size")
            if (size == 0L) {
                // Consume optional trailers until the empty line.
                while (true) {
                    val trailer = readAsciiLine(input, 8192) ?: break
                    if (trailer.isEmpty()) break
                }
                return body.toByteArray()
            }
            if (size > MAX_RESPONSE || body.size() + size > MAX_RESPONSE) throw IllegalStateException("doh_response_too_large")
            var remaining = size.toInt()
            val buf = ByteArray(4096)
            while (remaining > 0) {
                val n = input.read(buf, 0, minOf(buf.size, remaining))
                if (n < 0) throw java.io.EOFException("chunk_data_ended_early")
                if (n == 0) continue
                body.write(buf, 0, n)
                remaining -= n
            }
            val cr = input.read()
            val lf = input.read()
            if (cr != '\r'.code || lf != '\n'.code) throw IllegalStateException("chunk_crlf_missing")
        }
    }

    private fun readAsciiLine(input: java.io.InputStream, max: Int): String? {
        val out = ByteArrayOutputStream()
        while (out.size() < max) {
            val b = input.read()
            if (b < 0) return if (out.size() == 0) null else out.toByteArray().toString(Charsets.US_ASCII)
            if (b == '\n'.code) {
                val bytes = out.toByteArray()
                val end = if (bytes.isNotEmpty() && bytes.last().toInt() == '\r'.code) bytes.size - 1 else bytes.size
                return String(bytes, 0, end, Charsets.US_ASCII)
            }
            out.write(b)
        }
        throw IllegalStateException("http_line_too_long")
    }

    private fun physicalNetworks(): List<Network> {
        val cm = service.getSystemService(VpnService.CONNECTIVITY_SERVICE) as ConnectivityManager
        return cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) network else null
        }
    }

    fun shutdown() {
        executor.shutdownNow()
        runCatching { executor.awaitTermination(1, TimeUnit.SECONDS) }
    }
}
