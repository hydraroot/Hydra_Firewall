package com.hydra.firewall.vpn

import android.os.SystemClock
import android.net.VpnService
import android.os.Process
import com.hydra.firewall.security.ThreatSignatureStore
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.Severity
import android.util.Log
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.net.InetSocketAddress
import java.nio.channels.ClosedChannelException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * IPv4 UDP forwarding adapter.
 *
 * Each application 5-tuple gets its own protected connected DatagramChannel.
 * The socket is protected before connect(), then multiplexed on one Selector.
 * No UDP NAT table is shared between unrelated application flows.
 */
class UdpForwardingEngine(
    private val service: VpnService,
    private val tunWriter: TunPacketWriter,
    private val uidResolver: UidResolver,
    private val ruleEngine: RuleEngine,
    initialNetwork: NetworkKind
) {
    companion object {
        private const val TAG = "UdpForwardingEngine"
        private const val SELECT_TIMEOUT_MS = 100L
        private const val IDLE_TIMEOUT_MS = 60_000L
        private const val IDLE_SWEEP_INTERVAL_MS = 1_000L
        private const val MAX_SESSIONS = 256
        private const val MAX_UDP_PACKET = 65_535
        private const val MAX_PENDING_TUN_PACKETS = 512
        private const val MAX_SESSION_QUEUE_DATAGRAMS = 64
        private const val MAX_SESSION_QUEUE_BYTES = 256 * 1024
        // Cap on datagrams drained from one session per selector wakeup, so a
        // single busy flow cannot starve the other sessions on this thread.
        private const val MAX_DATAGRAMS_PER_READ = 32
    }

    private val running = AtomicBoolean(false)
    private val packetQueue = ConcurrentLinkedQueue<PendingTunPacket>()
    private val pendingPacketCount = AtomicInteger(0)
    private val sessions = ConcurrentHashMap<SessionKey, UdpSession>()
    private val sessionCounter = AtomicInteger(0)
    private var lastIdleSweepElapsedMs = 0L
    private val pendingNetwork = java.util.concurrent.atomic.AtomicReference(initialNetwork)
    private val policyRefresh = AtomicBoolean(false)
    private var currentNetwork = initialNetwork
    private lateinit var selector: Selector
    private lateinit var thread: Thread
    private lateinit var dnsTlsProxy: SecureDnsProxy

    private data class PendingTunPacket(val packet: ByteArray, val ip: IPv4Header)

    fun start() {
        if (!running.compareAndSet(false, true)) return
        selector = Selector.open()
        dnsTlsProxy = SecureDnsProxy(service)
        thread = Thread({ runLoop() }, "FirewallUdpEngine").apply { start() }
    }

    fun submitTunPacket(packet: ByteArray, ip: IPv4Header) {
        if (!running.get()) return
        if (pendingPacketCount.get() >= MAX_PENDING_TUN_PACKETS) {
            DiagnosticLogger.logServiceEvent("UDP TUN QUEUE DROP reason=overload limit=$MAX_PENDING_TUN_PACKETS")
            return
        }
        packetQueue.add(PendingTunPacket(packet, ip))
        pendingPacketCount.incrementAndGet()
        selector.wakeup()
    }

    fun onNetworkChanged(kind: NetworkKind) {
        pendingNetwork.set(kind)
        if (::selector.isInitialized) selector.wakeup()
    }

    fun refreshPolicies() {
        policyRefresh.set(true)
        if (::selector.isInitialized) selector.wakeup()
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        if (::dnsTlsProxy.isInitialized) dnsTlsProxy.shutdown()
        if (::selector.isInitialized) selector.wakeup()
        packetQueue.clear()
        pendingPacketCount.set(0)
        if (::thread.isInitialized && Thread.currentThread() !== thread) {
            try {
                thread.join(1500)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    fun activeSessions(): Int = sessionCounter.get()

    private fun runLoop() {
        try {
            while (running.get()) {
                applyPolicyUpdates()
                drainTunQueue()
                processTimers(System.currentTimeMillis())

                selector.select(SELECT_TIMEOUT_MS)
                val iterator = selector.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    if (!key.isValid()) continue
                    val session = key.attachment() as? UdpSession ?: continue
                    try {
                        if (key.isReadable()) handleRead(key, session)
                        if (key.isValid() && key.isWritable()) handleWrite(session)
                        if (key.isValid()) updateInterestOps(session)
                    } catch (e: Exception) {
                        Log.e(TAG, "UDP socket event error for ${session.key}", e)
                        closeSession(session)
                    }
                }
            }
        } catch (e: Exception) {
            if (running.get()) Log.e(TAG, "UDP event loop terminated", e)
        } finally {
            sessions.values.toList().forEach(::closeSession)
            try { selector.close() } catch (_: Exception) { }
        }
    }

    private fun applyPolicyUpdates() {
        val next = pendingNetwork.get()
        val networkChanged = next != currentNetwork
        if (networkChanged) {
            currentNetwork = next
            DiagnosticLogger.logServiceEvent("NETWORK CHANGED: ${currentNetwork.displayName} (UDP) RECONNECT_SESSIONS")
            // Protected UDP sockets are bound to the previous physical network.
            // Close them on a transition; the next app datagram creates a fresh socket.
            sessions.values.toList().forEach(::closeSession)
            policyRefresh.set(false)
            return
        }

        // Do not scan every session on every 100ms selector wakeup. TCP already
        // uses this event-driven pattern; UDP now revalidates only on an explicit
        // rule refresh (UI changes, lifecycle changes, or the service's 30s guard).
        if (policyRefresh.getAndSet(false)) enforceCurrentPolicies()
    }

    private fun enforceCurrentPolicies() {
        for (session in sessions.values.toList()) {
            val allowed = ruleEngine.isAllowed(session.uid, currentNetwork, session.key.dstAddr, "UDP", session.key.dstPort)
            session.markPolicyChecked()
            session.invalidateQuicResult()
            if (!allowed) {
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "BLOCKED_ACTIVE network=${currentNetwork.displayName}")
                closeSession(session)
            }
        }
    }

    private fun drainTunQueue() {
        var pending = packetQueue.poll()
        while (pending != null) {
            pendingPacketCount.decrementAndGet()
            try {
                handleTunPacket(pending.packet, pending.ip)
            } catch (e: Exception) {
                Log.w(TAG, "UDP TUN packet processing failed", e)
            }
            pending = packetQueue.poll()
        }
    }

    private fun handleTunPacket(packet: ByteArray, ip: IPv4Header) {
        val udp = UdpHeader.parse(packet, ip.headerLength, ip.totalLength) ?: return
        if (!Ipv4TransportChecksum.isValidUdp(packet, ip, udp)) {
            DiagnosticLogger.logServiceEvent("UDP CHECKSUM INVALID src=${ip.sourceAddress.hostAddress} dst=${ip.destinationAddress.hostAddress}")
            return
        }
        val key = SessionKey(
            protocol = UidResolver.PROTOCOL_UDP,
            srcAddr = ip.sourceAddress,
            srcPort = udp.sourcePort,
            dstAddr = ip.destinationAddress,
            dstPort = udp.destinationPort
        )

        val payloadOffset = ip.headerLength + 8
        val payloadLength = udp.payloadLength
        if (payloadOffset < 0 || payloadOffset + payloadLength > ip.totalLength || payloadOffset + payloadLength > packet.size) return
        val payload = if (payloadLength == 0) ByteArray(0) else packet.copyOfRange(
            payloadOffset,
            payloadOffset + payloadLength
        )

        // DNS/UDP must be a structurally valid DNS query before secure-DNS interception.
        if (udp.destinationPort == 53 && payload.isNotEmpty() && !DnsMessageValidator.isQuery(payload)) {
            DiagnosticLogger.logServiceEvent("DNS MALFORMED BLOCK src=${formatEndpoint(key.srcAddr, key.srcPort)} dst=${formatEndpoint(key.dstAddr, 53)}")
            return
        }

        // FIX130: the app-level first-connection decision must happen before
        // the normal ad/tracker blocklist. Otherwise the first DNS query from a
        // new app can be silently consumed by the downloaded blocklist and the
        // user never sees the permission prompt. Threat domains remain
        // authoritative and are blocked before prompting.
        if (udp.destinationPort == 53 && payload.isNotEmpty()) {
            val preflightQueryName = DnsMessageValidator.extractQueryName(payload)
            val dnsResolution = uidResolver.resolve(key, currentNetwork)
            val preflightThreatMatch = if (ruleEngine.isThreatProtectionEnabled(dnsResolution.uid, dnsResolution.packageName)) {
                preflightQueryName?.let { ThreatSignatureStore.matchDomain(service, it) }
            } else null
            if (preflightThreatMatch != null) {
                DiagnosticLogger.logServiceEvent(
                    "DNS FIRST_CONNECTION BYPASS threat=${preflightThreatMatch.match.name} uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"}"
                )
                            } else {
                val policyEvaluation = ruleEngine.evaluateApplicationPolicyDetailed(
                    dnsResolution.uid, currentNetwork, "UDP", 53, key.dstAddr
                )
                when (policyEvaluation.decision) {
                    RuleEngine.Decision.BLOCK -> {
                        DiagnosticLogger.logPolicyBlocked(
                            key, dnsResolution.uid, dnsResolution.packageName, currentNetwork, "DNS/UDP", payload.size + 28,
                            policyEvaluation.reasonCode, policyEvaluation.reasonDetail
                        )
                        return
                    }
                    RuleEngine.Decision.PROMPT -> {
                        val rule = ruleEngine.getRule(dnsResolution.uid)
                        DecisionRequestManager.request(
                            context = service,
                            key = key,
                            uid = dnsResolution.uid,
                            packageName = dnsResolution.packageName,
                            network = currentNetwork,
                            protocolLabel = "UDP",
                            initialWifiAllowed = rule.wifiAllowed,
                            initialMobileAllowed = rule.mobileAllowed
                        ) { wifiAllowed, mobileAllowed ->
                            RuleStore(service).apply {
                                setWifiAllowed(dnsResolution.uid, wifiAllowed)
                                setMobileAllowed(dnsResolution.uid, mobileAllowed)
                            }
                            DiagnosticLogger.logServiceEvent(
                                "ACCESS_DECISION_APPLIED uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"} dns_pending=discarded_wait_for_fresh_query"
                            )
                        }
                        DiagnosticLogger.logServiceEvent(
                            "DNS FIRST_CONNECTION PROMPT uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"} network=${currentNetwork.displayName} domain=${preflightQueryName ?: "unknown"}"
                        )
                                                return
                    }
                    RuleEngine.Decision.ALLOW -> Unit
                }
            }

            // Domain (ad/tracker) blocklist: answered locally, entirely on-device,
            // after the app-level permission is known.
            val queryName = preflightQueryName
            val threatMatch = preflightThreatMatch
            val scopedDomainAllow = queryName != null && threatMatch == null &&
                ConnectionExceptionStore.isDomainAllowed(service, dnsResolution.uid, queryName, dnsResolution.packageName)
            val customDecision = when {
                scopedDomainAllow -> CustomDomainRuleStore.Action.ALLOW
                else -> queryName?.let { CustomDomainRuleStore.decision(service, it) }
            }
            val publicBlocklisted = customDecision == null && DomainBlockStore.enabled && DomainBlockStore.isBlocked(queryName ?: "")
            val bypassPublicBlocklist = ruleEngine.shouldBypassOptionalDomainFilter(
                dnsResolution.uid, dnsResolution.packageName
            )
            val customRuleBlocks = when (customDecision) {
                CustomDomainRuleStore.Action.BLOCK -> true
                CustomDomainRuleStore.Action.ALLOW -> false
                null -> null
            }
            val domainBlocked = DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = threatMatch != null,
                customRuleBlocks = customRuleBlocks,
                publicBlocklisted = publicBlocklisted,
                bypassOptionalBlocklist = bypassPublicBlocklist
            )
            if (queryName != null && publicBlocklisted && bypassPublicBlocklist && threatMatch == null) {
                DiagnosticLogger.logServiceEvent(
                    "DOMAIN COMPAT BYPASS DNS name=$queryName uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"} reason=ESSENTIAL"
                )
            }
            if (queryName != null && domainBlocked) {
                val qtype = DnsBlockResponseBuilder.readQuestionType(payload)
                val response = DnsBlockResponseBuilder.build(payload, qtype)
                if (response != null) {
                    try {
                        val reply = UdpPacketBuilder.build(
                            source = ip.destinationAddress,
                            destination = ip.sourceAddress,
                            sourcePort = 53,
                            destinationPort = udp.sourcePort,
                            payload = response
                        )
                        tunWriter.write(reply)
                        val domainReasonCode = when {
                            threatMatch != null -> "THREAT_DOMAIN"
                            customDecision == CustomDomainRuleStore.Action.BLOCK -> "CUSTOM_DOMAIN_BLOCK"
                            else -> "AD_TRACKER_BLOCKLIST"
                        }
                        val domainReasonDetail = listOfNotNull(
                            queryName,
                            threatMatch?.match?.name,
                            threatMatch?.match?.family,
                            threatMatch?.match?.source
                        ).joinToString(" • ")
                        ConnectionHistory.add(
                            dnsResolution.uid, dnsResolution.packageName, "DNS/UDP", currentNetwork,
                            formatEndpoint(key.srcAddr, key.srcPort), formatEndpoint(key.dstAddr, 53),
                            allowed = false, event = "BLOCKED-DOMAIN-DNS",
                            reasonCode = domainReasonCode, reasonDetail = domainReasonDetail
                        )
                        TrafficAnalyzerStore.recordDns(dnsResolution.uid, dnsResolution.packageName, queryName, true)
                        if (threatMatch != null) {
                            ThreatSignatureStore.recordNetworkBlock(service)
                            SecurityEventStore.record(service, "THREAT_NETWORK_BLOCK", "Threat blocked: ${threatMatch.match.name}", "DNS ${queryName} • ${threatMatch.match.family ?: "network threat"}", threatMatch.match.severity)
                            NotificationHelper.notifyThreatBlocked(service, dnsResolution.packageName, queryName, threatMatch.match.family, threatMatch.match.severity)
                            DiagnosticLogger.logServiceEvent("THREAT BLOCKED dns=$queryName source=${threatMatch.match.source}")
                                                    } else {
                            val reason = if (customDecision == CustomDomainRuleStore.Action.BLOCK) "CUSTOM_DOMAIN" else "BLOCKLIST"
                            DiagnosticLogger.logServiceEvent("DOMAIN BLOCKED dns=$queryName reason=$reason src=${formatEndpoint(key.srcAddr, key.srcPort)}")
                                                    }
                    } catch (e: Exception) {
                        DiagnosticLogger.logServiceEvent("DOMAIN BLOCK RESPONSE FAILED dns=$queryName err=${e.message}")
                    }
                }
                return
            }
            if (queryName != null) {
                TrafficAnalyzerStore.recordDns(dnsResolution.uid, dnsResolution.packageName, queryName, false)
                DiagnosticLogger.logServiceEvent(
                    "DNS_QUERY uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"} name=$queryName qtype=${DnsBlockResponseBuilder.readQuestionType(payload)} server=${key.dstAddr.hostAddress}"
                )
                            }
        }

        // Optional encrypted DNS path: never send IPv4 UDP/53 directly when
        // Secure DNS is enabled. The original destination IP/port are kept in
        // the synthetic response so the application sees the DNS server it
        // queried, while the actual lookup travels over protected TLS/853.
        if (payload.isNotEmpty() && udp.destinationPort == 53 && ruleEngine.isSecureDnsEnabled()) {
            val dnsResolution = uidResolver.resolve(key, currentNetwork)
            if (!ruleEngine.shouldBypassSecureDns(dnsResolution.uid, dnsResolution.packageName)) {
                handleSecureDnsDatagram(key, payload, dnsResolution)
                return
            }
            DiagnosticLogger.logServiceEvent(
                "DNS COMPAT BYPASS uid=${dnsResolution.uid} pkg=${dnsResolution.packageName ?: "unknown"} reason=PROTECTED_APP_COMPAT"
            )
                    }

        var session = sessions[key]
        if (session == null) {
            if (sessionCounter.get() >= MAX_SESSIONS) {
                DiagnosticLogger.logUdpRuntime(key, Process.INVALID_UID, null, "SESSION_LIMIT_REACHED=$MAX_SESSIONS")
                return
            }
            val resolution = uidResolver.resolve(key, currentNetwork)
            val policyEvaluation = ruleEngine.evaluateDetailed(
                resolution.uid, currentNetwork, key.dstAddr,
                if (key.protocol == 6) "TCP" else "UDP", key.dstPort
            )
            when (policyEvaluation.decision) {
                RuleEngine.Decision.BLOCK -> {
                    DiagnosticLogger.logPolicyBlocked(
                        key, resolution.uid, resolution.packageName, currentNetwork, "UDP", payload.size + 28,
                        policyEvaluation.reasonCode, policyEvaluation.reasonDetail
                    )
                    return
                }
                RuleEngine.Decision.PROMPT -> {
                    val rule = ruleEngine.getRule(resolution.uid)
                    DecisionRequestManager.request(
                        context = service,
                        key = key,
                        uid = resolution.uid,
                        packageName = resolution.packageName,
                        network = currentNetwork,
                        protocolLabel = "UDP",
                        initialWifiAllowed = rule.wifiAllowed,
                        initialMobileAllowed = rule.mobileAllowed
                    ) { wifiAllowed, mobileAllowed ->
                        RuleStore(service).apply {
                            setWifiAllowed(resolution.uid, wifiAllowed)
                            setMobileAllowed(resolution.uid, mobileAllowed)
                        }
                        // Do not replay a stale UDP datagram after a long
                        // user decision. The application will send the next
                        // datagram under the newly saved rule.
                        DiagnosticLogger.logServiceEvent(
                            "ACCESS_DECISION_APPLIED uid=${resolution.uid} pkg=${resolution.packageName ?: "unknown"} udp_pending=discarded_wait_for_fresh_datagram"
                        )
                    }
                    return
                }
                RuleEngine.Decision.ALLOW -> Unit
            }
            session = createSession(key, resolution.uid, resolution.packageName) ?: return
            DiagnosticLogger.logUdpRuntime(key, session.uid, session.packageName, "FIRST_SEEN network=${currentNetwork.displayName}")
            DiagnosticLogger.logUdpFirstSeen(key, resolution, payload.size, policyEvaluation.reasonCode, policyEvaluation.reasonDetail)
            TrafficAnalyzerStore.recordConnection(resolution.uid, resolution.packageName, "UDP", key.dstAddr.hostAddress ?: "?", key.dstPort, "CONNECT")
            TrafficStatsStore.recordConnection(resolution.uid, resolution.packageName)
        }

        // Initial policy was checked before the session was created. Keep dynamic
        // policy responsive without repeating full PackageManager/SharedPreferences
        // and threat-IP work for every QUIC/UDP datagram.
        val policyNow = SystemClock.elapsedRealtime()
        if (session.needsPolicyRecheck(policyNow)) {
            val sessionPolicy = ruleEngine.evaluateDetailed(
                session.uid, currentNetwork, session.key.dstAddr, "UDP", session.key.dstPort
            )
            session.markPolicyChecked(policyNow)
            session.invalidateQuicResult()
            if (sessionPolicy.decision != RuleEngine.Decision.ALLOW) {
                DiagnosticLogger.logPolicyBlocked(
                    session.key, session.uid, session.packageName, currentNetwork, "UDP",
                    payload.size + 28, sessionPolicy.reasonCode, sessionPolicy.reasonDetail,
                    updateBlockedStats = false
                )
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "BLOCKED network=${currentNetwork.displayName}")
                closeSession(session)
                return
            }
        }

        val looksQuic = QuicDetector.isLikelyQuicUdp(payload, session.key.dstPort)
        val quicPolicy = if (!looksQuic) {
            QuicProtection.Result(false)
        } else {
            session.cachedQuicResult(policyNow) ?: QuicProtection.inspect(
                service, ruleEngine, session.uid, session.packageName,
                session.key.dstAddr, session.key.dstPort, payload
            ).also { session.cacheQuicResult(it, policyNow) }
        }
        if (quicPolicy.blocked) {
            val detail = listOf(quicPolicy.reason, quicPolicy.domain).filterNotNull().filter { it.isNotBlank() }.joinToString(" • ")
            ConnectionHistory.add(
                session.uid, session.packageName, "UDP", currentNetwork,
                formatEndpoint(session.key.srcAddr, session.key.srcPort),
                formatEndpoint(session.key.dstAddr, session.key.dstPort),
                allowed = false, event = "BLOCKED-QUIC",
                reasonCode = "QUIC_POLICY_BLOCK", reasonDetail = detail
            )
            DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "BLOCKED ${quicPolicy.reason}${quicPolicy.domain?.let { " domain=$it" } ?: ""}")
            closeSession(session)
            return
        }

        session.lastActivityMs = System.currentTimeMillis()
        TrafficStatsStore.recordTx(session.uid, session.packageName, payload.size)
        if (looksQuic) {
            DiagnosticLogger.logUdpData(session.key, session.uid, session.packageName, "QUIC/UDP DATA", payload.size)
            TrafficAnalyzerStore.recordData(session.uid, session.packageName, "UDP", session.key.dstAddr.hostAddress ?: "?", session.key.dstPort, payload.size, "QUIC/UDP DATA")
        }
        if (!queueOrSendDatagram(session, payload)) {
            closeSession(session)
        }
        updateInterestOps(session)
    }

    private fun handleSecureDnsDatagram(key: SessionKey, payload: ByteArray, resolution: UidResolver.Resolution) {
        val policyEvaluation = ruleEngine.evaluateDetailed(
            resolution.uid, currentNetwork, key.dstAddr,
            if (key.protocol == 6) "TCP" else "UDP", key.dstPort
        )
        when (policyEvaluation.decision) {
            RuleEngine.Decision.BLOCK -> {
                DiagnosticLogger.logPolicyBlocked(
                    key, resolution.uid, resolution.packageName, currentNetwork, "DNS/UDP", payload.size + 28,
                    policyEvaluation.reasonCode, policyEvaluation.reasonDetail
                )
                return
            }
            RuleEngine.Decision.PROMPT -> {
                val rule = ruleEngine.getRule(resolution.uid)
                DecisionRequestManager.request(
                    context = service,
                    key = key,
                    uid = resolution.uid,
                    packageName = resolution.packageName,
                    network = currentNetwork,
                    protocolLabel = "UDP",
                    initialWifiAllowed = rule.wifiAllowed,
                    initialMobileAllowed = rule.mobileAllowed
                ) { wifiAllowed, mobileAllowed ->
                    RuleStore(service).apply {
                        setWifiAllowed(resolution.uid, wifiAllowed)
                        setMobileAllowed(resolution.uid, mobileAllowed)
                    }
                    DiagnosticLogger.logServiceEvent(
                        "ACCESS_DECISION_APPLIED uid=${resolution.uid} pkg=${resolution.packageName ?: "unknown"} udp_pending=discarded_wait_for_fresh_datagram"
                    )
                }
                return
            }
            RuleEngine.Decision.ALLOW -> Unit
        }

        TrafficStatsStore.recordConnection(resolution.uid, resolution.packageName)
        TrafficStatsStore.recordTx(resolution.uid, resolution.packageName, payload.size)
        ConnectionHistory.add(
            resolution.uid, resolution.packageName, "DNS/UDP", currentNetwork,
            formatEndpoint(key.srcAddr, key.srcPort), formatEndpoint(key.dstAddr, 53),
            allowed = true, event = "DNS-OVER-TLS",
            reasonCode = policyEvaluation.reasonCode, reasonDetail = policyEvaluation.reasonDetail
        )
        DiagnosticLogger.logServiceEvent(
            "DNS OVER TLS query uid=${if (resolution.uid == android.os.Process.INVALID_UID) "INVALID" else resolution.uid} pkg=${resolution.packageName ?: "unknown"} dst=${key.dstAddr.hostAddress}"
        )
                dnsTlsProxy.query(payload) { response ->
            if (response == null) {
                DiagnosticLogger.logServiceEvent("DNS OVER TLS FAILED dst=${key.dstAddr.hostAddress}")
                                return@query
            }
            try {
                val reply = UdpPacketBuilder.build(
                    source = key.dstAddr,
                    destination = key.srcAddr,
                    sourcePort = 53,
                    destinationPort = key.srcPort,
                    payload = response
                )
                tunWriter.write(reply)
                if (DnsMessageValidator.isResponse(response)) {
                    DnsIpCorrelationStore.recordResponse(resolution.uid, response)
                }
                TrafficStatsStore.recordRx(resolution.uid, resolution.packageName, response.size)
                DiagnosticLogger.logServiceEvent(
                    "DNS OVER TLS response uid=${if (resolution.uid == android.os.Process.INVALID_UID) "INVALID" else resolution.uid} bytes=${response.size}"
                )
                            } catch (e: Exception) {
                DiagnosticLogger.logServiceEvent("DNS OVER TLS RESPONSE_FAILED: ${e.message}")
            }
        }
    }

    private fun createSession(key: SessionKey, uid: Int, packageName: String?): UdpSession? {
        val channel = try {
            DatagramChannel.open()
        } catch (e: IOException) {
            DiagnosticLogger.logUdpRuntime(key, uid, packageName, "SOCKET_CREATE_FAILED")
            return null
        }

        var registeredSession: UdpSession? = null
        try {
            // Critical anti-loop order: bind to the physical network and then
            // protect the socket from being captured by the VPN itself.
            if (!service.bindUpstreamSocketToPhysicalNetworkCompat(channel.socket())) {
                channel.close()
                DiagnosticLogger.logUdpRuntime(key, uid, packageName, "SOCKET_NETWORK_BIND_FAILED")
                return null
            }
            if (!service.protect(channel.socket())) {
                channel.close()
                DiagnosticLogger.logUdpRuntime(key, uid, packageName, "SOCKET_PROTECT_FAILED")
                return null
            }
            channel.configureBlocking(false)
            channel.connect(InetSocketAddress(key.dstAddr, key.dstPort))
            val session = UdpSession(key, uid, packageName, channel).apply { markPolicyChecked() }

            // Do not overwrite a live 5-tuple. If selector registration fails
            // after publication, the catch block removes this exact entry and
            // restores the local counter before returning.
            val existing = sessions.putIfAbsent(key, session)
            if (existing != null) {
                channel.close()
                return existing
            }
            sessionCounter.incrementAndGet()
            registeredSession = session
            session.selectionKey = channel.register(selector, SelectionKey.OP_READ, session)
            return session
        } catch (e: Exception) {
            registeredSession?.let { session ->
                session.closed = true
                try { session.selectionKey?.cancel() } catch (_: Exception) { }
                if (sessions.remove(key, session)) sessionCounter.decrementAndGet()
            }
            try { channel.close() } catch (_: Exception) { }
            DiagnosticLogger.logUdpRuntime(key, uid, packageName, "SESSION_CREATE_FAILED: ${e.javaClass.simpleName}")
            return null
        }
    }

    private fun enqueuePendingDatagram(session: UdpSession, buffer: ByteBuffer): Boolean {
        val bytes = buffer.capacity()
        if (session.toSocket.size >= MAX_SESSION_QUEUE_DATAGRAMS ||
            session.queuedBytes > MAX_SESSION_QUEUE_BYTES - bytes) {
            DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "REMOTE_QUEUE_OVERFLOW")
            return false
        }
        if (!UdpPendingDatagramBudget.tryReserve(bytes)) {
            // UDP is best-effort: under process-wide pressure drop only this
            // datagram instead of tearing down an otherwise healthy session.
            // Rate-limit diagnostics globally so overload cannot flood logs.
            val drops = UdpPendingDatagramBudget.recordQueueDrop()
            if (drops == 1L || drops % 500L == 0L) {
                DiagnosticLogger.logUdpRuntime(
                    session.key, session.uid, session.packageName,
                    "GLOBAL_UDP_QUEUE_FULL_DROP bytes=$bytes totalDrops=$drops"
                )
            }
            return true
        }
        session.toSocket.addLast(buffer)
        session.queuedBytes += bytes
        return true
    }

    private fun queueOrSendDatagram(session: UdpSession, payload: ByteArray): Boolean {
        if (payload.size > 65_507) return false
        if (session.toSocket.isNotEmpty()) {
            return enqueuePendingDatagram(session, ByteBuffer.wrap(payload.copyOf()))
        }

        return try {
            val buffer = ByteBuffer.wrap(payload)
            val written = session.channel.write(buffer)
            when {
                written == payload.size -> true
                written == 0 -> enqueuePendingDatagram(session, buffer)
                else -> {
                    DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "PARTIAL_DATAGRAM_WRITE")
                    false
                }
            }
        } catch (e: IOException) {
            DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "REMOTE_WRITE_ERROR: ${e.message}")
            false
        }
    }

    private fun handleRead(key: SelectionKey, session: UdpSession) {
        // Bounded per-session drain: a single UDP flow receiving a burst
        // (e.g. a busy media stream) could otherwise keep this selector
        // thread inside one session's while(true) indefinitely, starving
        // every other TCP/UDP session sharing the same thread. Reading up
        // to MAX_DATAGRAMS_PER_READ per selector wakeup keeps things fair;
        // if more data is still pending, the socket stays readable and gets
        // serviced again on the next loop iteration (fair round-robin).
        var datagrams = 0
        while (datagrams < MAX_DATAGRAMS_PER_READ) {
            val buffer = ByteBuffer.allocate(MAX_UDP_PACKET)
            val bytes = try {
                session.channel.read(buffer)
            } catch (e: Exception) {
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "REMOTE_READ_ERROR: ${e.message}")
                closeSession(session)
                return
            }
            if (bytes <= 0) return
            buffer.flip()
            val data = ByteArray(bytes)
            buffer.get(data)

            val packet = try {
                UdpPacketBuilder.build(
                    source = session.key.dstAddr,
                    destination = session.key.srcAddr,
                    sourcePort = session.key.dstPort,
                    destinationPort = session.key.srcPort,
                    payload = data
                )
            } catch (e: Exception) {
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "PACKET_BUILD_FAILED")
                closeSession(session)
                return
            }

            try {
                tunWriter.write(packet)
                session.lastActivityMs = System.currentTimeMillis()
                if (session.key.dstPort == 53 && DnsMessageValidator.isResponse(data)) {
                    DnsIpCorrelationStore.recordResponse(session.uid, data)
                    DiagnosticLogger.logServiceEvent(
                        "DNS_RESPONSE uid=${session.uid} pkg=${session.packageName ?: "unknown"} rcode=${data[3].toInt() and 0x0F} answers=${((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)} bytes=${data.size}"
                    )
                                    }
                TrafficStatsStore.recordRx(session.uid, session.packageName, data.size)
                DiagnosticLogger.logUdpData(session.key, session.uid, session.packageName, "S2C_DATA", data.size)
            } catch (e: IOException) {
                closeSession(session)
                return
            }
            datagrams++
        }
    }

    private fun handleWrite(session: UdpSession) {
        while (session.toSocket.isNotEmpty()) {
            val buffer = session.toSocket.first()
            val isEmptyDatagram = !buffer.hasRemaining()
            val written = try {
                session.channel.write(buffer)
            } catch (e: IOException) {
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "REMOTE_WRITE_ERROR: ${e.message}")
                closeSession(session)
                return
            }
            // A zero-length UDP payload is a valid datagram. DatagramChannel
            // reports 0 bytes for it even when the empty datagram was sent.
            if (written == 0 && !isEmptyDatagram) return
            if (buffer.hasRemaining()) {
                // DatagramChannel should write a whole datagram or fail; never split one datagram.
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "PARTIAL_DATAGRAM_WRITE")
                closeSession(session)
                return
            }
            session.toSocket.removeFirstOrNull()?.let {
                val bytes = it.capacity()
                session.queuedBytes = (session.queuedBytes - bytes).coerceAtLeast(0)
                if (!UdpPendingDatagramBudget.release(bytes)) {
                    DiagnosticLogger.logServiceEvent("UDP QUEUE BUDGET RELEASE MISMATCH bytes=$bytes")
                }
            }
        }
    }

    private fun updateInterestOps(session: UdpSession) {
        val key = session.selectionKey ?: return
        if (!key.isValid() || session.closed) return
        var ops = SelectionKey.OP_READ
        if (session.needsSocketWrite()) ops = ops or SelectionKey.OP_WRITE
        key.interestOps(ops)
    }

    private fun processTimers(now: Long) {
        uidResolver.purgeExpired()
        // This timer runs every selector timeout. A 60s idle timeout does not need
        // a full session-map walk every 100ms; one sweep per second is sufficient.
        val elapsedNow = SystemClock.elapsedRealtime()
        if (elapsedNow - lastIdleSweepElapsedMs < IDLE_SWEEP_INTERVAL_MS) return
        lastIdleSweepElapsedMs = elapsedNow
        // Policy revalidation is event-driven via policyRefresh / refreshPolicies().
        // Never rescan every UDP session from this periodic idle-expiry timer.
        for (session in sessions.values.toList()) {
            if (now - session.lastActivityMs > IDLE_TIMEOUT_MS) {
                DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "IDLE_TIMEOUT")
                closeSession(session)
            }
        }
    }

    private fun closeSession(session: UdpSession) {
        if (session.closed) return
        session.closed = true
        try { session.selectionKey?.cancel() } catch (_: Exception) { }
        try { session.channel.close() } catch (_: Exception) { }
        while (session.toSocket.isNotEmpty()) {
            val bytes = session.toSocket.removeFirst().capacity()
            session.queuedBytes = (session.queuedBytes - bytes).coerceAtLeast(0)
            if (!UdpPendingDatagramBudget.release(bytes)) {
                DiagnosticLogger.logServiceEvent("UDP QUEUE BUDGET RELEASE MISMATCH bytes=$bytes")
            }
        }
        session.queuedBytes = 0
        if (sessions.remove(session.key, session)) sessionCounter.decrementAndGet()
        DiagnosticLogger.logUdpRuntime(session.key, session.uid, session.packageName, "CLOSED")
    }

    private fun formatEndpoint(addr: java.net.InetAddress, port: Int): String {
        val host = addr.hostAddress ?: "?"
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }

}
