package com.hydra.firewall.vpn

import android.net.VpnService
import android.util.Log
import com.hydra.firewall.security.ThreatSignatureStore
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.Severity
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.min
import java.security.SecureRandom

/**
 * V1.3-alpha1: IPv4/TCP forwarding + per-UID Wi-Fi/mobile rules.
 *
 * Architecture:
 *   blocking TUN reader thread -> queue -> single Selector thread
 *   Selector thread owns all sockets and mutable TCP session state.
 *
 * UDP is handled by UdpForwardingEngine. IPv6 remains unsupported.
 */
class TcpForwardingEngine(
    private val service: VpnService,
    private val tunOut: TunPacketWriter,
    private val uidResolver: UidResolver,
    private val ruleEngine: RuleEngine,
    initialNetwork: NetworkKind
) {
    companion object {
        private const val TAG = "TcpForwardingEngine"
        private const val LOCAL_MSS = 1460
        private const val SELECT_TIMEOUT_MS = 100L
        private const val CONNECT_TIMEOUT_MS = 10_000L
        private const val IDLE_TIMEOUT_MS = 5 * 60_000L
        private const val READ_CHUNK = 16 * 1024
        private const val MAX_SESSIONS = 128
        private const val MAX_QUEUED_PACKETS = 2048
        private const val MAX_QUEUED_BYTES = 4 * 1024 * 1024
        private const val MAX_DRAIN_PER_LOOP = 256
        private val random = SecureRandom()
    }

    private val running = AtomicBoolean(false)
    private val packetQueue = ConcurrentLinkedQueue<PendingTunPacket>()
    private val queuedPackets = AtomicInteger(0)
    private val queuedBytes = AtomicInteger(0)
    private val queueDrops = java.util.concurrent.atomic.AtomicLong(0)
    private val sessions = ConcurrentHashMap<SessionKey, TcpSession>()
    private val sessionCounter = AtomicInteger(0)
    private val pendingNetwork = AtomicReference(initialNetwork)
    private val policyRefresh = AtomicBoolean(false)
    private var currentNetwork = initialNetwork
    private lateinit var selector: Selector
    private lateinit var thread: Thread

    fun start() {
        if (!running.compareAndSet(false, true)) return
        selector = Selector.open()
        thread = Thread({ runLoop() }, "FirewallTcpEngine").apply { start() }
    }

    private data class PendingTunPacket(val packet: ByteArray, val ip: IPv4Header)

    fun submitTunPacket(packet: ByteArray, ip: IPv4Header) {
        if (!running.get()) return
        if (queuedPackets.get() >= MAX_QUEUED_PACKETS || queuedBytes.get() + packet.size > MAX_QUEUED_BYTES) {
            // Backpressure: se descarta; TCP retransmite. Evita crecimiento ilimitado de memoria.
            val n = queueDrops.incrementAndGet()
            if (n == 1L || n % 500L == 0L) DiagnosticLogger.logServiceEvent("TCP QUEUE FULL drops=$n")
            return
        }
        queuedPackets.incrementAndGet()
        queuedBytes.addAndGet(packet.size)
        packetQueue.add(PendingTunPacket(packet, ip))
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
        if (::selector.isInitialized) selector.wakeup()
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

                if (packetQueue.isEmpty()) selector.select(SELECT_TIMEOUT_MS) else selector.selectNow()
                val iterator = selector.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    if (!key.isValid()) continue
                    val session = key.attachment() as? TcpSession ?: continue
                    try {
                        if (key.isConnectable()) handleConnect(key, session)
                        if (key.isValid() && key.isReadable()) handleRead(key, session)
                        if (key.isValid() && key.isWritable()) handleWrite(key, session)
                        if (key.isValid()) updateInterestOps(session)
                    } catch (e: Exception) {
                        Log.e(TAG, "socket event error for ${session.key}", e)
                        sendResetAndClose(session)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP event loop terminated", e)
        } finally {
            sessions.values.toList().forEach { closeSession(it, sendReset = false) }
            try { selector.close() } catch (_: Exception) { }
        }
    }

    private fun drainTunQueue() {
        var processed = 0
        while (processed < MAX_DRAIN_PER_LOOP) {
            val pending = packetQueue.poll() ?: return
            queuedPackets.decrementAndGet()
            queuedBytes.addAndGet(-pending.packet.size)
            processed++
            try {
                handleTcpFromTun(pending.packet, pending.ip)
            } catch (e: Exception) {
                Log.w(TAG, "TUN packet processing failed", e)
            }
        }
    }

    private fun applyPolicyUpdates() {
        val next = pendingNetwork.get()
        val networkChanged = next != currentNetwork
        if (networkChanged) {
            currentNetwork = next
        }
        val refresh = policyRefresh.getAndSet(false)
        if (networkChanged) {
            DiagnosticLogger.logServiceEvent("NETWORK CHANGED: ${currentNetwork.displayName} (TCP) RECONNECT_SESSIONS")
            // Force TCP reconnects after a Wi-Fi/mobile transition. Protected sockets
            // created on the previous underlying network are not reused, regardless
            // of whether the new network would still allow the session.
            for (session in sessions.values.toList()) {
                DiagnosticLogger.logTcpRuntime(
                    session.key, session.uid, session.packageName,
                    "NETWORK_CHANGED_RESET network=${currentNetwork.displayName}"
                )
                sendResetAndClose(session)
            }
        }
        if (refresh) {
            for (session in sessions.values.toList()) {
                if (!ruleEngine.isAllowed(session.uid, currentNetwork, session.key.dstAddr, if (session.key.protocol == 6) "TCP" else "UDP", session.key.dstPort)) {
                    DiagnosticLogger.logTcpRuntime(
                        session.key, session.uid, session.packageName,
                        "BLOCKED_ACTIVE network=${currentNetwork.displayName}"
                    )
                    sendResetAndClose(session)
                }
            }
        }
    }

    private fun handleTcpFromTun(packet: ByteArray, ip: IPv4Header) {
        val tcp = TcpHeader.parse(packet, ip.headerLength, ip.totalLength) ?: return
        val key = SessionKey(
            protocol = UidResolver.PROTOCOL_TCP,
            srcAddr = ip.sourceAddress,
            srcPort = tcp.sourcePort,
            dstAddr = ip.destinationAddress,
            dstPort = tcp.destinationPort
        )
        val payloadOffset = ip.headerLength + tcp.headerLength
        val payloadLength = ip.totalLength - payloadOffset
        if (payloadLength < 0 || payloadOffset + payloadLength > packet.size) return
        val payload = if (payloadLength == 0) ByteArray(0) else packet.copyOfRange(
            payloadOffset,
            payloadOffset + payloadLength
        )

        var session = sessions[key]
        if (session == null) {
            if (!tcp.isSyn || tcp.isAck || tcp.isRst) return
            session = createSession(key, tcp, packet.size) ?: return
        }

        if (!ruleEngine.isAllowed(session.uid, currentNetwork, session.key.dstAddr, if (session.key.protocol == 6) "TCP" else "UDP", session.key.dstPort)) {
            DiagnosticLogger.logPolicyBlocked(
                key, session.uid, session.packageName, currentNetwork, "TCP", packet.size
            )
            sendResetAndClose(session)
            return
        }

        session.lastActivityMs = System.currentTimeMillis()

        if (tcp.isRst) {
            DiagnosticLogger.logTcpRuntime(key, session.uid, session.packageName, "RST_FROM_APP")
            closeSession(session, sendReset = false)
            return
        }

        if (tcp.isSyn) {
            if (session.state == TcpSession.State.SYN_RECV) {
                sendSynAck(session, retransmit = true)
            }
            return
        }

        if (tcp.isAck) {
            updatePeerWindow(session, tcp.window)
            processAck(session, tcp.acknowledgmentNumber)
        }

        if (session.state == TcpSession.State.CONNECTING) {
            return
        }

        if (session.state == TcpSession.State.SYN_RECV) {
            if (tcp.isAck && TcpSequence.compare(tcp.acknowledgmentNumber, session.localNextSeq) == 0) {
                session.localAckedSeq = session.localNextSeq
                session.state = TcpSession.State.ESTABLISHED
                DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "ESTABLISHED")
            } else {
                return
            }
        }

        if (payload.isNotEmpty()) {
            acceptClientPayload(session, tcp.sequenceNumber, payload)
        }

        if (tcp.isFin) {
            handleClientFin(session, tcp.sequenceNumber, payload.size)
        }
        tryApplyPendingFin(session)

        maybeCloseAfterAcks(session)
        maybeSendServerFin(session)
        updateInterestOps(session)
    }

    private fun createSession(key: SessionKey, tcp: TcpHeader, packetSize: Int): TcpSession? {
        if (sessionCounter.get() >= MAX_SESSIONS) {
            DiagnosticLogger.logServiceEvent("TCP SESSION LIMIT REACHED: $MAX_SESSIONS")
            sendStatelessResetForSyn(key, tcp)
            return null
        }

        val resolution = uidResolver.resolve(key, currentNetwork)
        if (resolution.uid == android.os.Process.INVALID_UID) {
            // Android 7 may publish the new socket in /proc/net slightly after
            // the SYN reaches the TUN. Do NOT answer with RST here: that turns a
            // transient attribution miss into a permanent connection failure and
            // prevents the background UID recovery/prompt path from ever getting
            // a fresh SYN. Drop the SYN and let the application retransmit while
            // UidResolver keeps retrying in the background.
            DiagnosticLogger.logServiceEvent(
                "TCP_UID_PENDING src=${key.srcAddr.hostAddress}:${key.srcPort} dst=${key.dstAddr.hostAddress}:${key.dstPort} network=${currentNetwork.displayName} via=${resolution.resolvedVia}"
            )
            return null
        }
        when (ruleEngine.evaluate(resolution.uid, currentNetwork, key.dstAddr, if (key.protocol == 6) "TCP" else "UDP", key.dstPort)) {
            RuleEngine.Decision.BLOCK -> {
                DiagnosticLogger.logPolicyBlocked(key, resolution.uid, resolution.packageName, currentNetwork, "TCP", packetSize)
                sendStatelessResetForSyn(key, tcp)
                return null
            }
            RuleEngine.Decision.PROMPT -> {
                val rule = ruleEngine.getRule(resolution.uid)
                val requested = DecisionRequestManager.request(
                    context = service,
                    key = key,
                    uid = resolution.uid,
                    packageName = resolution.packageName,
                    network = currentNetwork,
                    protocolLabel = "TCP",
                    initialWifiAllowed = rule.wifiAllowed,
                    initialMobileAllowed = rule.mobileAllowed
                ) { wifiAllowed, mobileAllowed ->
                    RuleStore(service).apply {
                        setWifiAllowed(resolution.uid, wifiAllowed)
                        setMobileAllowed(resolution.uid, mobileAllowed)
                    }
                    // Do not replay the original SYN: the user may take
                    // several seconds/minutes to decide and the app can have
                    // abandoned that TCP 5-tuple already. Replaying a stale
                    // SYN can resolve to INVALID uid and immediately trigger
                    // an app RST. The next fresh connection attempt will see
                    // the saved explicit rule and proceed normally.
                    DiagnosticLogger.logServiceEvent(
                        "ACCESS_DECISION_APPLIED uid=${resolution.uid} pkg=${resolution.packageName ?: "unknown"} tcp_pending=discarded_wait_for_fresh_syn"
                    )
                }
                if (!requested) {
                    // Another SYN from the same app is already covered by the
                    // open decision prompt; discard this packet and wait for
                    // the first fresh SYN after the user decides.
                }
                return null
            }
            RuleEngine.Decision.ALLOW -> Unit
        }

        val localInitialSeq = random.nextLong() and 0xFFFF_FFFFL
        val channel = try {
            SocketChannel.open()
        } catch (e: IOException) {
            DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "SOCKET_CREATE_FAILED")
            sendStatelessResetForSyn(key, tcp)
            return null
        }

        try {
            // Critical anti-loop order: bind to the physical network and then
            // protect the socket from being captured by the VPN itself.
            if (!service.bindUpstreamSocketToPhysicalNetworkCompat(channel.socket())) {
                channel.close()
                DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "SOCKET_NETWORK_BIND_FAILED")
                sendStatelessResetForSyn(key, tcp)
                return null
            }
            if (!service.protect(channel.socket())) {
                channel.close()
                DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "SOCKET_PROTECT_FAILED")
                sendStatelessResetForSyn(key, tcp)
                return null
            }

            channel.socket().tcpNoDelay = true
            channel.configureBlocking(false)
            val session = TcpSession(
                key = key,
                uid = resolution.uid,
                packageName = resolution.packageName,
                peerMss = (tcp.mss ?: LOCAL_MSS).coerceIn(536, LOCAL_MSS),
                peerWindowScale = (tcp.windowScale ?: 0).coerceIn(0, 14),
                localMss = LOCAL_MSS,
                channel = channel,
                clientInitialSeq = tcp.sequenceNumber,
                localInitialSeq = localInitialSeq
            )
            session.clientWindow = (tcp.window.toLong() shl session.peerWindowScale)
                .coerceAtMost(64L * 1024 * 1024)

            val connectedImmediately = try {
                channel.connect(InetSocketAddress(key.dstAddr, key.dstPort))
            } catch (e: IOException) {
                Log.w(TAG, "connect failed immediately for $key", e)
                false
            }

            sessions[key] = session
            sessionCounter.incrementAndGet()

            if (connectedImmediately) {
                onRemoteConnected(session)
            } else if (channel.isConnectionPending) {
                session.selectionKey = channel.register(selector, SelectionKey.OP_CONNECT, session)
                DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "CONNECTING")
            } else {
                channel.close()
                sessions.remove(key)
                sessionCounter.decrementAndGet()
                DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "CONNECT_FAILED")
                sendStatelessResetForSyn(key, tcp)
                return null
            }

            DiagnosticLogger.logTcpOpen(key, resolution.uid, resolution.packageName)
            TrafficAnalyzerStore.recordConnection(resolution.uid, resolution.packageName, "TCP", key.dstAddr.hostAddress ?: "?", key.dstPort, "CONNECT")
            TrafficStatsStore.recordConnection(resolution.uid, resolution.packageName)
            return session
        } catch (e: Exception) {
            try { channel.close() } catch (_: Exception) { }
            sessions.remove(key)
            if (sessionCounter.get() > 0) sessionCounter.decrementAndGet()
            DiagnosticLogger.logTcpRuntime(key, resolution.uid, resolution.packageName, "SESSION_CREATE_FAILED: ${e.javaClass.simpleName}")
            sendStatelessResetForSyn(key, tcp)
            return null
        }
    }

    private fun onRemoteConnected(session: TcpSession) {
        session.state = TcpSession.State.SYN_RECV
        sendSynAck(session, retransmit = false)
        session.selectionKey = session.channel.register(selector, SelectionKey.OP_READ, session)
        DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "REMOTE_CONNECTED + SYN_ACK_SENT")
    }

    private fun sendSynAck(session: TcpSession, retransmit: Boolean) {
        val now = System.currentTimeMillis()
        if (retransmit && session.synAckRetries >= TcpSession.MAX_RETRANSMISSIONS) {
            sendResetAndClose(session)
            return
        }
        val packet = TcpPacketBuilder.build(
            session = session,
            seq = session.localInitialSeq,
            ack = session.clientExpectedSeq,
            syn = true,
            ackFlag = true
        )
        tunOut.write(packet)
        if (!session.synAckSent) {
            session.localNextSeq = TcpSequence.add(session.localNextSeq, 1)
            session.synAckSent = true
        } else if (retransmit) {
            session.synAckRetries++
        }
        session.lastSynAckMs = now
        session.lastActivityMs = now
    }

    private fun sendAck(session: TcpSession, ack: Long = session.clientExpectedSeq) {
        val packet = TcpPacketBuilder.build(
            session = session,
            seq = session.localNextSeq,
            ack = ack,
            ackFlag = true
        )
        tunOut.write(packet)
    }

    private fun acceptClientPayload(session: TcpSession, sequence: Long, payload: ByteArray): Boolean {
        if (payload.isEmpty()) return true
        val expected = session.clientExpectedSeq
        val available = TcpSession.RECEIVE_BUFFER_LIMIT - session.toSocketBytes - session.reassembly.bufferedBytes()
        if (available <= 0) {
            sendAck(session, expected)
            return false
        }

        val boundedPayload = if (payload.size > available) payload.copyOf(available) else payload
        val result = session.reassembly.offer(sequence, boundedPayload, expected)
        if (result.type == TcpReassembly.ResultType.OUT_OF_WINDOW) {
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "OUT_OF_ORDER expected=$expected got=$sequence"
            )
        } else if (result.type == TcpReassembly.ResultType.OVERFLOW) {
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "TCP_REASSEMBLY_OVERFLOW buffered=${session.reassembly.bufferedBytes()}"
            )
        }

        result.delivered.forEach { queueClientData(session, it) }
        session.clientExpectedSeq = result.nextExpected
        sendAck(session, session.clientExpectedSeq)
        return result.type != TcpReassembly.ResultType.OUT_OF_WINDOW &&
            result.type != TcpReassembly.ResultType.OVERFLOW &&
            boundedPayload.size == payload.size
    }

    private fun queueClientData(session: TcpSession, data: ByteArray) {
        if (data.isEmpty()) return
        session.toSocket.addLast(ByteBuffer.wrap(data))
        session.toSocketBytes += data.size
        TrafficStatsStore.recordTx(session.uid, session.packageName, data.size)
        DiagnosticLogger.logTcpData(session.key, session.uid, session.packageName, "C2S_DATA", data.size)
        TrafficAnalyzerStore.recordData(session.uid, session.packageName, "TCP", session.key.dstAddr.hostAddress ?: "?", session.key.dstPort, data.size, "C2S_DATA")
        inspectForTlsSecurity(session, data)
        updateInterestOps(session)
    }

    /**
     * Inspects the first TLS ClientHello independently of the optional JA3
     * telemetry feature. The ad/tracker domain blocklist is a traffic-control
     * feature, so it must remain effective even when TLS fingerprint logging
     * is disabled.
     *
     * This closes an important bypass: an app can resolve an advertising host
     * before the VPN starts, use a cached address, or use a resolver path that
     * does not expose a normal UDP/53 query to us. The TLS SNI is still visible
     * for ordinary TLS ClientHello traffic without MITM. When that SNI matches
     * the active local domain blocklist, the TCP session is reset immediately.
     */
    private fun inspectForTlsSecurity(session: TcpSession, data: ByteArray) {
        val acc = session.tlsFingerprintAccumulator
        val result = TlsFingerprintInspector.feed(acc, data)

        if (result == null) return

        val destination = session.key.dstAddr.hostAddress ?: "?"
        val sni = result.sni
        
        // Enforce signed threat intelligence first. A confirmed threat cannot be
        // whitelisted accidentally. User domain rules then override normal ad/tracker
        // blocklists, and the public blocklist is the final fallback.
        val threatMatch = if (ruleEngine.isThreatProtectionEnabled(session.uid, session.packageName)) {
            sni?.let { ThreatSignatureStore.matchDomain(service, it) }
        } else null
        val customDecision = sni?.let { CustomDomainRuleStore.decision(service, it) }
        val publicBlocklisted = customDecision == null &&
            DomainBlockStore.enabled && DomainBlockStore.isBlocked(sni ?: "")
        val bypassPublicBlocklist = ruleEngine.shouldBypassOptionalDomainFilter(session.uid, session.packageName)
        val sniProtectionEnabled = ruleEngine.isTlsSniProtectionEnabled(session.uid, session.packageName)
        val domainBlocked = when (customDecision) {
            CustomDomainRuleStore.Action.BLOCK -> true
            CustomDomainRuleStore.Action.ALLOW -> false
            null -> publicBlocklisted && !bypassPublicBlocklist && sniProtectionEnabled
        }
        if (sni != null && publicBlocklisted && bypassPublicBlocklist && threatMatch == null) {
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "DOMAIN COMPAT BYPASS TLS_SNI=$sni reason=ESSENTIAL_COMPAT"
            )
        }
        if (sni != null && (threatMatch != null || domainBlocked)) {
            ConnectionHistory.add(
                session.uid,
                session.packageName,
                "TCP",
                currentNetwork,
                formatEndpoint(session.key.srcAddr, session.key.srcPort),
                "$sni:${session.key.dstPort}",
                allowed = false,
                event = "BLOCKED-DOMAIN-SNI"
            )
            if (threatMatch != null) {
                ThreatSignatureStore.recordNetworkBlock(service)
                SecurityEventStore.record(service, "THREAT_NETWORK_BLOCK", "Threat blocked: ${threatMatch.match.name}", "HTTPS SNI ${sni} • ${threatMatch.match.family ?: "network threat"}", threatMatch.match.severity)
                NotificationHelper.notifyThreatBlocked(service, session.packageName, sni, threatMatch.match.family, threatMatch.match.severity)
                DiagnosticLogger.logTcpRuntime(
                    session.key, session.uid, session.packageName,
                    "THREAT BLOCKED TLS_SNI=$sni source=${threatMatch.match.source}"
                )
            } else {
                val reason = if (customDecision == CustomDomainRuleStore.Action.BLOCK) "CUSTOM_DOMAIN" else "BLOCKLIST"
                DiagnosticLogger.logTcpRuntime(
                    session.key, session.uid, session.packageName,
                    "DOMAIN BLOCKED TLS_SNI=$sni reason=$reason dst=$destination:${session.key.dstPort}"
                )
            }
            sendResetAndClose(session)
            return
        }

        // JA3/JA3N fingerprinting remains optional telemetry / known-bad
        // fingerprint enforcement. It is deliberately not required for the
        // domain blocklist to work.
        if (!TlsFingerprintStore.isEnabled() ||
            !ruleEngine.isTlsFingerprintProtectionEnabled(session.uid, session.packageName)) return

        val recorded = TlsFingerprintStore.record(session.uid, session.packageName, destination, session.key.dstPort, result)
        AppNetworkProfileStore.recordDestination(
            session.uid, session.packageName,
            recorded.sni ?: destination, session.key.dstPort
        )
        if (recorded.matchedBlocklist) {
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "TLS_FINGERPRINT_MATCH ja3=${result.ja3Hash} sni=${result.sni ?: "-"}"
            )
            if (TlsFingerprintStore.isBlockOnMatchEnabled() &&
                !ruleEngine.shouldBypassOptionalTlsFilter(session.uid, session.packageName, currentNetwork)) {
                sendResetAndClose(session)
            }
        }
    }

    private fun handleClientFin(session: TcpSession, sequence: Long, payloadLength: Int) {
        val expectedFin = TcpSequence.add(sequence, payloadLength.toLong())
        if (TcpSequence.compare(expectedFin, session.clientExpectedSeq) != 0) {
            session.pendingFinSequence = expectedFin
            session.pendingFinPayloadLength = 0
            sendAck(session, session.clientExpectedSeq)
            return
        }
        applyClientFin(session)
    }

    private fun tryApplyPendingFin(session: TcpSession) {
        val pending = session.pendingFinSequence ?: return
        if (TcpSequence.compare(pending, session.clientExpectedSeq) != 0) return
        session.pendingFinSequence = null
        session.pendingFinPayloadLength = 0
        applyClientFin(session)
    }

    private fun applyClientFin(session: TcpSession) {
        if (session.clientFinSeen) return
        session.clientFinSeen = true
        session.clientExpectedSeq = TcpSequence.add(session.clientExpectedSeq, 1)
        sendAck(session, session.clientExpectedSeq)
        if (!session.outputShutdown && session.toSocket.isEmpty()) {
            try {
                session.channel.socket().shutdownOutput()
                session.outputShutdown = true
                DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "C2S_FIN -> shutdownOutput")
            } catch (_: IOException) {
                sendResetAndClose(session)
            }
        }
    }

    private fun updatePeerWindow(session: TcpSession, rawWindow: Int) {
        session.clientWindow = (rawWindow.toLong() shl session.peerWindowScale)
            .coerceAtMost(64L * 1024 * 1024)
    }

    private fun processAck(session: TcpSession, ack: Long) {
        if (TcpSequence.compare(ack, session.localNextSeq) > 0) {
            DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "FUTURE_ACK")
            sendResetAndClose(session)
            return
        }
        if (TcpSequence.compare(ack, session.localAckedSeq) <= 0) return

        while (session.toClient.isNotEmpty()) {
            val first = session.toClient.first()
            val end = first.endSequence()
            if (TcpSequence.compare(ack, end) >= 0) {
                session.toClient.removeFirst()
                session.localAckedSeq = end
            } else {
                if (TcpSequence.compare(ack, first.sequence) > 0 && first.payload.isNotEmpty() && !first.fin) {
                    val trim = TcpSequence.distance(first.sequence, ack).toInt().coerceAtMost(first.payload.size)
                    if (trim > 0) {
                        first.payload = first.payload.copyOfRange(trim, first.payload.size)
                        first.sequence = ack
                        first.lastSentMs = System.currentTimeMillis()
                        session.localAckedSeq = ack
                    }
                }
                break
            }
        }

        if (TcpSequence.compare(ack, session.localAckedSeq) > 0) {
            session.localAckedSeq = ack
        }
        maybeCloseAfterAcks(session)
        maybeSendServerFin(session)
    }

    private fun handleConnect(key: SelectionKey, session: TcpSession) {
        try {
            if (!session.channel.finishConnect()) return
            key.interestOps(SelectionKey.OP_READ)
            onRemoteConnectedAfterPending(session)
        } catch (e: IOException) {
            DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "CONNECT_FAILED: ${e.message}")
            sendStatelessResetForSession(session)
            closeSession(session, sendReset = false)
        }
    }

    private fun onRemoteConnectedAfterPending(session: TcpSession) {
        session.state = TcpSession.State.SYN_RECV
        sendSynAck(session, retransmit = false)
        DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "REMOTE_CONNECTED + SYN_ACK_SENT")
    }

    private fun handleRead(key: SelectionKey, session: TcpSession) {
        if (session.state == TcpSession.State.SYN_RECV || !session.needsSocketRead()) return
        val maxPayload = min(
            session.peerMss,
            min(READ_CHUNK, session.availableClientWindow().toInt().coerceAtLeast(1))
        )
        if (maxPayload <= 0) return
        val buffer = ByteBuffer.allocate(maxPayload)
        val bytes = try {
            session.channel.read(buffer)
        } catch (e: IOException) {
            DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "REMOTE_READ_ERROR: ${e.message}")
            sendResetAndClose(session)
            return
        }
        when {
            bytes < 0 -> {
                session.remoteEof = true
                session.remoteReadClosed = true
                DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "REMOTE_EOF")
                maybeSendServerFin(session)
                key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
            }
            bytes == 0 -> Unit
            else -> {
                buffer.flip()
                val data = ByteArray(bytes)
                buffer.get(data)
                sendDataToClient(session, data)
            }
        }
    }

    private fun sendDataToClient(session: TcpSession, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val room = session.availableClientWindow().toInt()
            if (room <= 0) break
            val chunkSize = min(session.peerMss, min(room, data.size - offset))
            if (chunkSize <= 0) break
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            val seq = session.localNextSeq
            val packet = TcpPacketBuilder.build(
                session = session,
                seq = seq,
                ack = session.clientExpectedSeq,
                ackFlag = true,
                psh = true,
                payload = chunk
            )
            tunOut.write(packet)
            session.toClient.addLast(
                TcpPendingSegment(
                    sequence = seq,
                    payload = chunk,
                    psh = true,
                    lastSentMs = System.currentTimeMillis()
                )
            )
            session.localNextSeq = TcpSequence.add(session.localNextSeq, chunk.size.toLong())
            offset += chunk.size
        }
        if (offset > 0) {
            TrafficStatsStore.recordRx(session.uid, session.packageName, offset)
            session.lastActivityMs = System.currentTimeMillis()
            DiagnosticLogger.logTcpData(session.key, session.uid, session.packageName, "S2C_DATA", offset)
            TrafficAnalyzerStore.recordData(session.uid, session.packageName, "TCP", session.key.dstAddr.hostAddress ?: "?", session.key.dstPort, offset, "S2C_DATA")
        }
    }

    private fun maybeSendServerFin(session: TcpSession) {
        if (!session.remoteEof || session.serverFinSent || session.toClient.isNotEmpty()) return
        if (session.availableClientWindow() <= 0) return
        val seq = session.localNextSeq
        val packet = TcpPacketBuilder.build(
            session = session,
            seq = seq,
            ack = session.clientExpectedSeq,
            ackFlag = true,
            fin = true
        )
        tunOut.write(packet)
        session.toClient.addLast(
            TcpPendingSegment(
                sequence = seq,
                payload = ByteArray(0),
                fin = true,
                lastSentMs = System.currentTimeMillis()
            )
        )
        session.localNextSeq = TcpSequence.add(session.localNextSeq, 1)
        session.serverFinSequence = seq
        session.serverFinSent = true
        DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "S2C_FIN_SENT")
    }

    private fun handleWrite(key: SelectionKey, session: TcpSession) {
        while (session.toSocket.isNotEmpty()) {
            val buffer = session.toSocket.first()
            val written = try {
                session.channel.write(buffer)
            } catch (e: IOException) {
                DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "REMOTE_WRITE_ERROR: ${e.message}")
                sendResetAndClose(session)
                return
            }
            if (written < 0) {
                sendResetAndClose(session)
                return
            }
            session.toSocketBytes -= written
            if (!buffer.hasRemaining()) session.toSocket.removeFirst()
            if (written == 0) break
        }

        if (session.clientFinSeen && !session.outputShutdown && session.toSocket.isEmpty()) {
            try {
                session.channel.socket().shutdownOutput()
                session.outputShutdown = true
            } catch (_: IOException) {
                sendResetAndClose(session)
                return
            }
        }
        updateInterestOps(session)
    }

    private fun updateInterestOps(session: TcpSession) {
        val key = session.selectionKey ?: return
        if (!key.isValid()) return
        val ops = when (session.state) {
            TcpSession.State.CONNECTING -> SelectionKey.OP_CONNECT
            TcpSession.State.SYN_RECV -> 0
            TcpSession.State.ESTABLISHED,
            TcpSession.State.CLOSING -> {
                var wanted = 0
                if (session.needsSocketRead()) wanted = wanted or SelectionKey.OP_READ
                if (session.needsSocketWrite()) wanted = wanted or SelectionKey.OP_WRITE
                wanted
            }
            TcpSession.State.CLOSED -> 0
        }
        key.interestOps(ops)
    }

    private fun processTimers(now: Long) {
        uidResolver.purgeExpired()
        for (session in sessions.values.toList()) {
            when {
                session.state == TcpSession.State.CONNECTING && now - session.createdMs > CONNECT_TIMEOUT_MS -> {
                    DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "CONNECT_TIMEOUT")
                    sendStatelessResetForSession(session)
                    closeSession(session, sendReset = false)
                }
                now - session.lastActivityMs > IDLE_TIMEOUT_MS -> {
                    DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "IDLE_TIMEOUT")
                    sendResetAndClose(session)
                }
            }

            if (session.state == TcpSession.State.SYN_RECV && session.synAckSent &&
                now - session.lastSynAckMs >= TcpSession.RETRANSMIT_MS) {
                try {
                    sendSynAck(session, retransmit = true)
                } catch (_: IOException) {
                    sendResetAndClose(session)
                }
            }

            val first = session.toClient.firstOrNull()
            if (first != null && now - first.lastSentMs >= TcpSession.RETRANSMIT_MS) {
                if (first.retransmissions >= TcpSession.MAX_RETRANSMISSIONS) {
                    sendResetAndClose(session)
                } else {
                    resendSegment(session, first)
                }
            }
            maybeSendServerFin(session)
        }
    }

    private fun resendSegment(session: TcpSession, segment: TcpPendingSegment) {
        try {
            val packet = TcpPacketBuilder.build(
                session = session,
                seq = segment.sequence,
                ack = session.clientExpectedSeq,
                ackFlag = true,
                fin = segment.fin,
                psh = segment.psh,
                payload = segment.payload
            )
            tunOut.write(packet)
            segment.lastSentMs = System.currentTimeMillis()
            segment.retransmissions++
            DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "RETRANSMIT seq=${segment.sequence}")
        } catch (_: IOException) {
            sendResetAndClose(session)
        }
    }

    private fun maybeCloseAfterAcks(session: TcpSession) {
        if (session.state == TcpSession.State.CLOSED) return
        val localFullyAcked = TcpSequence.compare(session.localAckedSeq, session.localNextSeq) == 0
        val bothDirectionsClosed = session.clientFinSeen && session.serverFinSent && session.toSocket.isEmpty() && localFullyAcked
        if (bothDirectionsClosed) closeSession(session, sendReset = false)
    }

    private fun sendStatelessResetForSyn(key: SessionKey, tcp: TcpHeader) {
        val packet = StatelessTcpPacketBuilder.buildIpv4Tcp(
            source = key.dstAddr,
            destination = key.srcAddr,
            sourcePort = key.dstPort,
            destinationPort = key.srcPort,
            seq = 0,
            ack = TcpSequence.add(tcp.sequenceNumber, 1),
            rst = true,
            ackFlag = true,
            window = 0
        )
        try { tunOut.write(packet) } catch (_: IOException) { }
    }

    private fun sendStatelessResetForSession(session: TcpSession) {
        val packet = StatelessTcpPacketBuilder.buildIpv4Tcp(
            source = session.key.dstAddr,
            destination = session.key.srcAddr,
            sourcePort = session.key.dstPort,
            destinationPort = session.key.srcPort,
            seq = session.localNextSeq,
            ack = session.clientExpectedSeq,
            rst = true,
            ackFlag = true,
            window = session.advertisedReceiveWindow()
        )
        try { tunOut.write(packet) } catch (_: IOException) { }
    }

    private fun sendResetAndClose(session: TcpSession) {
        sendStatelessResetForSession(session)
        closeSession(session, sendReset = false)
    }

    private fun closeSession(session: TcpSession, sendReset: Boolean) {
        if (session.state == TcpSession.State.CLOSED) return
        if (sendReset) sendStatelessResetForSession(session)
        session.state = TcpSession.State.CLOSED
        try { session.selectionKey?.cancel() } catch (_: Exception) { }
        try { session.channel.close() } catch (_: Exception) { }
        if (sessions.remove(session.key, session)) sessionCounter.decrementAndGet()
        DiagnosticLogger.logTcpRuntime(session.key, session.uid, session.packageName, "CLOSED")
    }

    /** Formats an IPv4/IPv6 endpoint without ambiguity for logs/history. */
    private fun formatEndpoint(addr: java.net.InetAddress, port: Int): String {
        val host = addr.hostAddress ?: "?"
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
}

private object StatelessTcpPacketBuilder {
    private val identification = AtomicInteger((System.nanoTime() and 0xFFFF).toInt())

    fun buildIpv4Tcp(
        source: java.net.InetAddress,
        destination: java.net.InetAddress,
        sourcePort: Int,
        destinationPort: Int,
        seq: Long,
        ack: Long,
        rst: Boolean,
        ackFlag: Boolean,
        window: Int
    ): ByteArray {
        require(source.address.size == 4 && destination.address.size == 4)
        val total = 40
        val p = ByteArray(total)
        p[0] = 0x45
        p[8] = 64
        p[9] = 6
        p[2] = (total ushr 8).toByte(); p[3] = total.toByte()
        val id = identification.getAndIncrement() and 0xFFFF
        p[4] = (id ushr 8).toByte(); p[5] = id.toByte()
        System.arraycopy(source.address, 0, p, 12, 4)
        System.arraycopy(destination.address, 0, p, 16, 4)
        val ipCsum = InternetChecksum.checksum(p, 0, 20)
        p[10] = (ipCsum ushr 8).toByte(); p[11] = ipCsum.toByte()

        val o = 20
        p[o] = (sourcePort ushr 8).toByte(); p[o + 1] = sourcePort.toByte()
        p[o + 2] = (destinationPort ushr 8).toByte(); p[o + 3] = destinationPort.toByte()
        p[o + 4] = (seq ushr 24).toByte(); p[o + 5] = (seq ushr 16).toByte(); p[o + 6] = (seq ushr 8).toByte(); p[o + 7] = seq.toByte()
        p[o + 8] = (ack ushr 24).toByte(); p[o + 9] = (ack ushr 16).toByte(); p[o + 10] = (ack ushr 8).toByte(); p[o + 11] = ack.toByte()
        p[o + 12] = 0x50
        p[o + 13] = ((if (rst) 0x04 else 0) or (if (ackFlag) 0x10 else 0)).toByte()
        p[o + 14] = (window ushr 8).toByte(); p[o + 15] = window.toByte()

        val pseudo = ByteArray(12)
        System.arraycopy(source.address, 0, pseudo, 0, 4)
        System.arraycopy(destination.address, 0, pseudo, 4, 4)
        pseudo[9] = 6
        pseudo[10] = 0
        pseudo[11] = 20
        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum, p, 20, 20)
        val c = (sum xor 0xFFFF) and 0xFFFF
        p[36] = (c ushr 8).toByte(); p[37] = c.toByte()
        return p
    }
}
