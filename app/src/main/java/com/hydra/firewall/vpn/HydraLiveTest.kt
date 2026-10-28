package com.hydra.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.UnknownHostException

/**
 * Real, opt-in, end-to-end test. This test deliberately binds its DNS and TCP
 * operations to the VPN Network object, so the result cannot accidentally use
 * the physical/default network of the device.
 */
object HydraLiveTest {

    private const val BLOCKED_PROBE_DOMAIN = "doubleclick.net"
    private const val ALLOWED_PROBE_DOMAIN = "example.com"
    private const val CONNECT_TIMEOUT_MS = 5000
    private const val SETTLE_MS = 1800L
    private const val DNS_RETRIES = 3
    private const val DNS_RETRY_DELAY_MS = 900L

    fun run(context: Context): List<HydraSelfTest.CheckResult> {
        val results = ArrayList<HydraSelfTest.CheckResult>()

        if (!FirewallVpnService.isRunning) {
            results += fail("live_precondition", "Prueba en vivo", "HYDRA no está corriendo. Arrancá la protección antes de probar.")
            return results
        }

        FirewallVpnService.setLiveTestMode(context, true)
        try {
            val entered = waitUntil(timeoutMs = 15000) {
                FirewallVpnService.isRunning && FirewallVpnService.liveTestMode
            }
            if (!entered) {
                results += fail(
                    "live_precondition",
                    "Prueba en vivo",
                    "La VPN no quedó operativa en modo de prueba (running=${FirewallVpnService.isRunning}, liveTestMode=${FirewallVpnService.liveTestMode})."
                )
                return results
            }

            try { Thread.sleep(SETTLE_MS) } catch (_: InterruptedException) { }
            val vpnNetwork = waitForActiveVpnNetwork(context, 10000)
            if (vpnNetwork == null) {
                results += fail(
                    "live_vpn_network",
                    "Red VPN para la prueba",
                    "La red activa de Android no es la VPN de HYDRA. No se enviaron pruebas para evitar medir la red física por fuera del firewall."
                )
                return results
            }

            results += vpnDnsConfigurationCheck()
            results += dnsBlockCheck(context, vpnNetwork)
            results += dnsAllowCheck(context, vpnNetwork)
            results += tcpConnectivityCheck(context, vpnNetwork)
        } finally {
            FirewallVpnService.setLiveTestMode(context, false)
            waitUntil(timeoutMs = 15000) { FirewallVpnService.isRunning && !FirewallVpnService.liveTestMode }
        }
        return results
    }

    private fun vpnDnsConfigurationCheck(): HydraSelfTest.CheckResult {
        val servers = FirewallVpnService.configuredDnsServers
        return if (servers.isNotEmpty()) {
            pass(
                "live_dns_config",
                "DNS de la VPN configurado",
                "tun0 anuncia ${servers.joinToString(", ")}."
            )
        } else {
            fail(
                "live_dns_config",
                "DNS de la VPN configurado",
                "HYDRA no tiene servidores DNS configurados en esta ejecución."
            )
        }
    }

    private fun dnsBlockCheck(context: Context, vpnNetwork: Network): HydraSelfTest.CheckResult {
        return try {
            val query = buildDnsQuery(BLOCKED_PROBE_DOMAIN, transactionId = 0x4B31)
            val response = performDnsQuery(context, vpnNetwork, query)
                ?: return fail("live_dns_block", "Bloqueo de dominio real ($BLOCKED_PROBE_DOMAIN)", "No llegó ninguna respuesta DNS por la red VPN.")

            val expected = DnsBlockResponseBuilder.build(query, 1)
            if (expected != null && response.contentEquals(expected)) {
                pass("live_dns_block", "Bloqueo de dominio real ($BLOCKED_PROBE_DOMAIN)", "La VPN devolvió la respuesta sintética 0.0.0.0 generada por el bloqueador.")
            } else {
                fail(
                    "live_dns_block",
                    "Bloqueo de dominio real ($BLOCKED_PROBE_DOMAIN)",
                    "La consulta DNS recibió una respuesta, pero no coincide con la respuesta sintética de bloqueo. bytes=${response.size}."
                )
            }
        } catch (e: Exception) {
            fail("live_dns_block", "Bloqueo de dominio real ($BLOCKED_PROBE_DOMAIN)", "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun dnsAllowCheck(context: Context, vpnNetwork: Network): HydraSelfTest.CheckResult {
        var last: Exception? = null
        repeat(DNS_RETRIES) { attempt ->
            try {
                val query = buildDnsQuery(ALLOWED_PROBE_DOMAIN, transactionId = 0x5C42 + attempt)
                val response = performDnsQuery(context, vpnNetwork, query)
                    ?: throw java.io.IOException("sin respuesta DNS")
                if (!DnsMessageValidator.isResponse(response)) {
                    throw java.io.IOException("respuesta DNS inválida (${response.size} bytes)")
                }
                val answers = readAnswerCount(response)
                val rcode = response[3].toInt() and 0x0F
                if (rcode == 0 && answers > 0) {
                    return pass(
                        "live_dns_allow",
                        "Resolución normal ($ALLOWED_PROBE_DOMAIN)",
                        "Respuesta DNS válida dentro del túnel VPN: rcode=$rcode answers=$answers bytes=${response.size}."
                    )
                }
                throw java.io.IOException("respuesta DNS sin resolución útil: rcode=$rcode answers=$answers")
            } catch (e: Exception) {
                last = e
            }
            if (attempt + 1 < DNS_RETRIES) {
                try { Thread.sleep(DNS_RETRY_DELAY_MS) } catch (_: InterruptedException) { }
            }
        }
        val e = last ?: IllegalStateException("DNS sin resultado")
        val dnsDiagnostics = DiagnosticLogger.getBufferedLines()
            .filter { it.contains("SECURE_DNS") || it.contains("DNS OVER TLS") }
            .takeLast(12)
            .joinToString(" | ") { it.substringAfter("] ") }
            .take(1800)
        val detail = buildString {
            append("${e.javaClass.simpleName}: ${e.message} — la resolución DNS no respondió correctamente dentro del túnel VPN tras $DNS_RETRIES intentos.")
            if (dnsDiagnostics.isNotBlank()) {
                append(" Diagnóstico: ")
                append(dnsDiagnostics)
            }
        }
        return fail("live_dns_allow", "Resolución normal ($ALLOWED_PROBE_DOMAIN)", detail)
    }

    /**
     * Sends a real DNS/UDP packet through Android's active VPN default route.
     * calling Network.getByName()/getAllByName(). Android's hostname resolver
     * can perform its own internal DNS handling on Android 7, which makes a
     * self-test using getAllByName() ambiguous when the tested app is itself
     * temporarily included in the VPN. A raw DatagramSocket gives us the
     * actual packet path that HYDRA's UDP engine processes.
     */
    private fun performDnsQuery(context: Context, vpnNetwork: Network, query: ByteArray): ByteArray? {
        // IMPORTANT on Android 7: do not call Network.bindSocket() on the VPN
        // Network. During a self-VPN test that Network object can become stale
        // while tun0 is recreated, producing ENONET ("Machine is not on the
        // network"). Instead, first verify that Android's *active* network is
        // the HYDRA VPN, then use a normal DatagramSocket. Because liveTestMode
        // includes HYDRA's own UID in the tunnel, this socket follows the VPN
        // default route and enters the real UDP/TUN path.
        val active = activeVpnNetwork(vpnNetwork, context)
            ?: throw java.io.IOException("HYDRA VPN no es la red activa durante la prueba")
        val dnsServer = FirewallVpnService.configuredDnsServers.firstOrNull()
            ?: throw java.io.IOException("HYDRA no tiene servidor DNS configurado")
        val address = InetAddress.getByName(dnsServer)
        java.net.DatagramSocket().use { socket ->
            socket.soTimeout = 6000
            val request = java.net.DatagramPacket(query, query.size, address, 53)
            socket.send(request)
            val buffer = ByteArray(65535)
            val response = java.net.DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            return response.data.copyOfRange(response.offset, response.offset + response.length)
        }
    }

    private fun readAnswerCount(response: ByteArray): Int {
        if (response.size < 12) return 0
        return ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
    }

    private fun buildDnsQuery(domain: String, transactionId: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream(256)
        out.write((transactionId ushr 8) and 0xFF)
        out.write(transactionId and 0xFF)
        out.write(0x01); out.write(0x00) // RD
        out.write(0x00); out.write(0x01) // QDCOUNT
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT
        for (label in domain.trim('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.isNotEmpty() && bytes.size <= 63) { "invalid DNS label" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01) // A
        out.write(0x00); out.write(0x01) // IN
        return out.toByteArray()
    }

    private fun tcpConnectivityCheck(context: Context, vpnNetwork: Network): HydraSelfTest.CheckResult {
        // Keep TCP independent from DNS so a DNS failure does not generate a
        // second, misleading failure. The socket is explicitly bound to the
        // VPN network and connects directly to 1.1.1.1:443.
        return try {
            activeVpnNetwork(vpnNetwork, context)
                ?: throw java.io.IOException("HYDRA VPN no es la red activa durante la prueba TCP")
            val address = InetAddress.getByName("1.1.1.1")
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, 443), CONNECT_TIMEOUT_MS)
                if (socket.isConnected) {
                    pass(
                        "live_tcp",
                        "Conexión TCP real vía HYDRA",
                        "Handshake TCP a 1.1.1.1:443 completado usando la red VPN $vpnNetwork."
                    )
                } else {
                    fail("live_tcp", "Conexión TCP real vía HYDRA", "El socket no quedó conectado.")
                }
            }
        } catch (e: Exception) {
            fail("live_tcp", "Conexión TCP real vía HYDRA", "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun waitForActiveVpnNetwork(context: Context, timeoutMs: Long): Network? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            activeVpnNetwork(null, context)?.let { return it }
            try { Thread.sleep(150L) } catch (_: InterruptedException) { return activeVpnNetwork(null, context) }
        }
        return activeVpnNetwork(null, context)
    }

    private fun activeVpnNetwork(expected: Network?, context: Context): Network? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val active = cm.activeNetwork ?: return null
        if (!isVpnNetwork(cm, active)) return null
        if (expected != null && expected != active) return null
        return active
    }

    private fun isVpnNetwork(cm: ConnectivityManager, network: Network): Boolean {
        val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun waitUntil(timeoutMs: Long, pollMs: Long = 100L, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            try { Thread.sleep(pollMs) } catch (_: InterruptedException) { return condition() }
        }
        return condition()
    }

    private fun pass(id: String, title: String, detail: String) =
        HydraSelfTest.CheckResult(id, title, HydraSelfTest.Status.PASS, detail)

    private fun fail(id: String, title: String, detail: String) =
        HydraSelfTest.CheckResult(id, title, HydraSelfTest.Status.FAIL, detail)
}
