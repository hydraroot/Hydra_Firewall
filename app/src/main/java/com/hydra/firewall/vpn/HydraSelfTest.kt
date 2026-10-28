package com.hydra.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Process
import com.hydra.firewall.security.ThreatSignatureStore
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress

/**
 * On-device self-check suite for HYDRA's own subsystems.
 *
 * IMPORTANT LIMITATION: HYDRA excludes its own package from the VPN tunnel
 * (`addDisallowedApplication(packageName)` in FirewallVpnService), so any
 * network call made from *this* app bypasses HYDRA entirely and cannot be
 * used to prove that other apps' traffic is actually being filtered.
 * These checks therefore fall into two groups:
 *   1) Parsing/logic checks that feed synthetic packets/messages directly
 *      into HYDRA's real code (Icmpv4Handler, DnsBlockResponseBuilder,
 *      TlsClientHello, ProcNetUidResolver, InternetChecksum) - these do
 *      exercise the exact code paths used on live traffic.
 *   2) Operational checks (VPN running, DNS configured, lists loaded,
 *      active sessions) that read HYDRA's own state.
 * Neither group proves "app X's packets are filtered right now"; that can
 * only be confirmed with an external device/ADB capture.
 */
object HydraSelfTest {

    enum class Status { PASS, WARN, FAIL }

    data class CheckResult(val id: String, val title: String, val status: Status, val detail: String)

    fun runAll(context: Context): List<CheckResult> {
        val results = ArrayList<CheckResult>()
        results += checkVpnRunning()
        results += checkVpnDns(context)
        results += checkNetworkValidated(context)
        results += checkIcmpv4Echo()
        results += checkDnsBlockResponse()
        results += checkTlsClientHelloParsing()
        results += checkProcNetUidColumn()
        results += checkChecksum()
        results += checkBlocklistLoaded(context)
        results += checkThreatPackLoaded(context)
        results += checkDiagnosticLogWritable(context)
        results += checkActiveSessions()
        return results
    }

    private fun checkVpnRunning(): CheckResult =
        if (FirewallVpnService.isRunning) {
            CheckResult("vpn_running", "Servicio VPN activo", Status.PASS, "HYDRA está corriendo.")
        } else {
            CheckResult("vpn_running", "Servicio VPN activo", Status.FAIL, "HYDRA no está corriendo: ningún otro chequeo de tráfico es representativo.")
        }

    private fun checkVpnDns(context: Context): CheckResult {
        val servers = FirewallVpnService.configuredDnsServers
        if (!FirewallVpnService.isRunning) {
            return CheckResult("vpn_dns", "DNS publicado en la VPN", Status.WARN, "VPN detenida, no hay DNS configurado.")
        }
        if (servers.isEmpty()) {
            return CheckResult("vpn_dns", "DNS publicado en la VPN", Status.FAIL, "LinkProperties.DnsAddresses quedaría vacío.")
        }
        val bad = servers.filter { host ->
            runCatching { InetAddress.getByName(host) }.getOrNull()?.let {
                it.isLinkLocalAddress || it.isLoopbackAddress || it.isMulticastAddress
            } ?: true
        }
        return if (bad.isEmpty()) {
            CheckResult("vpn_dns", "DNS publicado en la VPN", Status.PASS, servers.joinToString())
        } else {
            CheckResult("vpn_dns", "DNS publicado en la VPN", Status.FAIL, "Direcciones no válidas para tun0: ${bad.joinToString()}")
        }
    }

    private fun checkNetworkValidated(context: Context): CheckResult {
        if (!FirewallVpnService.isRunning) {
            return CheckResult("net_validated", "Red VPN validada por Android", Status.WARN, "VPN detenida.")
        }
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return CheckResult("net_validated", "Red VPN validada por Android", Status.WARN, "ConnectivityManager no disponible.")
        val vpnNetwork = cm.allNetworks.firstOrNull { net ->
            val caps = runCatching { cm.getNetworkCapabilities(net) }.getOrNull()
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
        val caps = vpnNetwork?.let { runCatching { cm.getNetworkCapabilities(it) }.getOrNull() }
        return when {
            caps == null -> CheckResult("net_validated", "Red VPN validada por Android", Status.WARN, "No se encontró la red VPN en ConnectivityManager (puede tardar unos segundos tras arrancar).")
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) -> CheckResult("net_validated", "Red VPN validada por Android", Status.PASS, "Transports=VPN, VALIDATED presente.")
            else -> CheckResult("net_validated", "Red VPN validada por Android", Status.FAIL, "Android no marcó la red VPN como VALIDATED todavía.")
        }
    }

    /** Feeds a synthetic ICMPv4 echo request into the real Icmpv4Handler and
     * checks the reply it writes, the same path used for live TUN packets. */
    private fun checkIcmpv4Echo(): CheckResult {
        return try {
            val request = buildEchoRequest("10.0.0.3", FirewallVpnService.VPN_ADDRESS)
            val parsed = IpParser.parse(request)
            if (parsed !is IpParser.Result.Icmpv4) {
                return CheckResult("icmpv4", "Respondedor ICMPv4 local", Status.FAIL, "IpParser no reconoció el paquete sintético como ICMPv4.")
            }
            val sink = ByteArrayOutputStream()
            val handled = Icmpv4Handler.handle(parsed.packet, parsed.header, TunPacketWriter(sink))
            val reply = sink.toByteArray()
            if (handled && reply.size == 28 && (reply[20].toInt() and 0xFF) == 0) {
                CheckResult("icmpv4", "Respondedor ICMPv4 local", Status.PASS, "Echo reply generado y checksums válidos.")
            } else {
                CheckResult("icmpv4", "Respondedor ICMPv4 local", Status.FAIL, "handled=$handled bytes=${reply.size}")
            }
        } catch (e: Exception) {
            CheckResult("icmpv4", "Respondedor ICMPv4 local", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** Builds a synthetic DNS query and checks DnsBlockResponseBuilder's
     * synthetic block response, the same code used by the blocklist path. */
    private fun checkDnsBlockResponse(): CheckResult {
        return try {
            val query = buildDnsQuery("selftest.hydra.invalid")
            if (!DnsMessageValidator.isQuery(query)) {
                return CheckResult("dns_block", "Respuesta DNS sintética (bloqueo)", Status.FAIL, "El query sintético no pasó DnsMessageValidator.isQuery.")
            }
            val name = DnsMessageValidator.extractQueryName(query)
            val response = DnsBlockResponseBuilder.build(query, 1)
            val valid = name == "selftest.hydra.invalid" && response != null &&
                response.size >= 12 && response[0] == query[0] && response[1] == query[1] &&
                DnsMessageValidator.isResponse(response)
            if (valid) {
                CheckResult("dns_block", "Respuesta DNS sintética (bloqueo)", Status.PASS, "Nombre extraído y respuesta 0.0.0.0 generada correctamente.")
            } else {
                CheckResult("dns_block", "Respuesta DNS sintética (bloqueo)", Status.FAIL, "name=$name responseSize=${response?.size}")
            }
        } catch (e: Exception) {
            CheckResult("dns_block", "Respuesta DNS sintética (bloqueo)", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** Feeds a minimal synthetic TLS ClientHello with an SNI extension into
     * the real parser used for domain/SNI filtering. */
    private fun checkTlsClientHelloParsing(): CheckResult {
        return try {
            val hello = buildMinimalClientHello("selftest.hydra.invalid")
            val info = TlsClientHello.tryParse(hello)
            if (info?.sni == "selftest.hydra.invalid") {
                CheckResult("tls_sni", "Parser de SNI en ClientHello", Status.PASS, "SNI extraído correctamente de un ClientHello sintético.")
            } else {
                CheckResult("tls_sni", "Parser de SNI en ClientHello", Status.FAIL, "sni=${info?.sni}")
            }
        } catch (e: Exception) {
            CheckResult("tls_sni", "Parser de SNI en ClientHello", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** Regression check for the FIX117 bug: verifies the UID column read
     * from a real-kernel-format /proc/net/tcp row is the correct one. */
    private fun checkProcNetUidColumn(): CheckResult {
        return try {
            val file = File.createTempFile("hydra-selftest-procnet", ".txt")
            file.writeText(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
                    " 0: 0200000A:9CBB 04030201:01BB 01 00000000:00000000 00:00000000 00000000 12345        0 999 1 0000000000000000 20 4 30 10 -1\n"
            )
            val uid = ProcNetUidResolver.debugReadUidFromFile(file, "0200000A", "9CBB", "04030201", "01BB")
            file.delete()
            if (uid == 12345) {
                CheckResult("procnet_uid", "Columna UID de /proc/net (Android 7-9)", Status.PASS, "Leyó uid=12345 de una fila con formato real del kernel.")
            } else {
                CheckResult("procnet_uid", "Columna UID de /proc/net (Android 7-9)", Status.FAIL, "Leyó uid=$uid, se esperaba 12345.")
            }
        } catch (e: Exception) {
            CheckResult("procnet_uid", "Columna UID de /proc/net (Android 7-9)", Status.WARN, "No se pudo ejecutar en este dispositivo: ${e.javaClass.simpleName}")
        }
    }

    private fun checkChecksum(): CheckResult {
        return try {
            val data = byteArrayOf(0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40.toByte(), 0x00, 0x40, 0x01, 0x00, 0x00,
                0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x03)
            val cs = InternetChecksum.checksum(data, 0, data.size)
            val patched = data.copyOf()
            patched[10] = (cs ushr 8).toByte(); patched[11] = cs.toByte()
            val verify = InternetChecksum.compute(patched, 0, patched.size)
            if (verify == 0xFFFF) {
                CheckResult("checksum", "Checksum de Internet (RFC 1071)", Status.PASS, "Checksum calculado y verificado: suma final 0xFFFF.")
            } else {
                CheckResult("checksum", "Checksum de Internet (RFC 1071)", Status.FAIL, "verify=$verify, se esperaba 65535 (0xFFFF).")
            }
        } catch (e: Exception) {
            CheckResult("checksum", "Checksum de Internet (RFC 1071)", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun checkBlocklistLoaded(context: Context): CheckResult {
        return try {
            DomainBlockStore.init(context)
            val info = DomainBlockStore.activeListInfo()
            if (info.domainCount > 0) {
                CheckResult("blocklist", "Lista de anuncios/rastreadores cargada", Status.PASS, "${info.domainCount} dominios (${info.source}, ${info.date}).")
            } else {
                CheckResult("blocklist", "Lista de anuncios/rastreadores cargada", Status.WARN, "0 dominios activos.")
            }
        } catch (e: Exception) {
            CheckResult("blocklist", "Lista de anuncios/rastreadores cargada", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun checkThreatPackLoaded(context: Context): CheckResult {
        return try {
            val status = ThreatSignatureStore.status(context)
            val indicatorTotal = status.domainCount + status.ipCount + status.urlCount + status.sha256Count
            val total = indicatorTotal + status.yaraRuleCount
            if (total > 0) {
                val detail = "${status.yaraRuleCount} reglas YARA + $indicatorTotal indicadores (versión ${status.packVersion})."
                CheckResult("threat_pack", "Paquete de amenazas cargado", Status.PASS, detail)
            } else {
                CheckResult("threat_pack", "Paquete de amenazas cargado", Status.WARN, "El paquete de amenazas no contiene indicadores ni reglas YARA activas.")
            }
        } catch (e: Exception) {
            CheckResult("threat_pack", "Paquete de amenazas cargado", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun checkDiagnosticLogWritable(context: Context): CheckResult {
        return try {
            val dir = context.getExternalFilesDir(null) ?: context.filesDir
            val file = File(dir, "hydra-diagnostic.log")
            if (!file.exists()) {
                CheckResult("log_file", "Log de diagnóstico (ADB)", Status.WARN, "Todavía no se creó ${file.name}; arrancá la VPN primero.")
            } else {
                val ageMs = System.currentTimeMillis() - file.lastModified()
                if (ageMs < 5 * 60_000L) {
                    CheckResult("log_file", "Log de diagnóstico (ADB)", Status.PASS, "Escrito hace ${ageMs / 1000}s, ${file.length()} bytes.")
                } else {
                    CheckResult("log_file", "Log de diagnóstico (ADB)", Status.WARN, "Sin escritura reciente (${ageMs / 1000}s), ${file.length()} bytes.")
                }
            }
        } catch (e: Exception) {
            CheckResult("log_file", "Log de diagnóstico (ADB)", Status.FAIL, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun checkActiveSessions(): CheckResult {
        if (!FirewallVpnService.isRunning) {
            return CheckResult("sessions", "Sesiones activas", Status.WARN, "VPN detenida.")
        }
        return CheckResult(
            "sessions", "Sesiones activas", Status.PASS,
            "TCP=${FirewallVpnService.activeTcpSessions} UDP=${FirewallVpnService.activeUdpSessions} red=${FirewallVpnService.currentNetworkKind.displayName}"
        )
    }

    // ---- Synthetic packet/message builders (test-only, no I/O) ----

    private fun buildEchoRequest(src: String, dst: String): ByteArray {
        val packet = ByteArray(28)
        packet[0] = 0x45
        packet[3] = 28
        packet[8] = 64
        packet[9] = IPv4Header.PROTOCOL_ICMP.toByte()
        InetAddress.getByName(src).address.copyInto(packet, destinationOffset = 12)
        InetAddress.getByName(dst).address.copyInto(packet, destinationOffset = 16)
        packet[20] = 8 // echo request
        packet[24] = 0x5E; packet[25] = 0x1F; packet[26] = 0x00; packet[27] = 0x01
        val icmpChecksum = InternetChecksum.checksum(packet, 20, 8)
        packet[22] = (icmpChecksum ushr 8).toByte(); packet[23] = icmpChecksum.toByte()
        val ipChecksum = InternetChecksum.checksum(packet, 0, 20)
        packet[10] = (ipChecksum ushr 8).toByte(); packet[11] = ipChecksum.toByte()
        return packet
    }

    private fun buildDnsQuery(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x12); out.write(0x34) // transaction id
        out.write(0x01); out.write(0x00) // flags: standard query, RD=1
        out.write(0x00); out.write(0x01) // QDCOUNT=1
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT
        for (label in name.split(".")) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01) // QTYPE A
        out.write(0x00); out.write(0x01) // QCLASS IN
        return out.toByteArray()
    }

    private fun buildMinimalClientHello(sni: String): ByteArray {
        val sniHost = sni.toByteArray(Charsets.US_ASCII)
        val serverNameEntry = ByteArrayOutputStream().apply {
            write(0x00) // name type: host_name
            write((sniHost.size ushr 8) and 0xFF); write(sniHost.size and 0xFF)
            write(sniHost)
        }.toByteArray()
        val serverNameListLen = serverNameEntry.size
        val extServerName = ByteArrayOutputStream().apply {
            write(0x00); write(0x00) // extension type: server_name
            write(0x00); write((serverNameListLen + 2) and 0xFF) // extension_data length
            write((serverNameListLen ushr 8) and 0xFF); write(serverNameListLen and 0xFF)
            write(serverNameEntry)
        }.toByteArray()

        val body = ByteArrayOutputStream().apply {
            write(0x03); write(0x03) // client_version TLS 1.2
            write(ByteArray(32)) // random
            write(0x00) // session_id length
            write(0x00); write(0x02) // cipher_suites length
            write(0x13); write(0x01) // TLS_AES_128_GCM_SHA256
            write(0x01); write(0x00) // compression_methods: 1 method, null
            write((extServerName.size ushr 8) and 0xFF); write(extServerName.size and 0xFF)
            write(extServerName)
        }.toByteArray()

        val handshake = ByteArrayOutputStream().apply {
            write(0x01) // handshake type: client_hello
            write((body.size ushr 16) and 0xFF); write((body.size ushr 8) and 0xFF); write(body.size and 0xFF)
            write(body)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(0x16) // content type: handshake
            write(0x03); write(0x01) // record version
            write((handshake.size ushr 8) and 0xFF); write(handshake.size and 0xFF)
            write(handshake)
        }.toByteArray()
    }
}
