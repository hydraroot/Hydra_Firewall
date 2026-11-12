package com.hydra.firewall.vpn

import android.net.VpnService
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.ThreatSignatureStore

/**
 * One shared SNI enforcement path for IPv4/TCP and IPv6/TCP.
 *
 * Call this only with bytes delivered by TcpReassembly, not raw TUN segments.
 * That keeps out-of-order TCP segments from producing different SNI decisions
 * between IPv4 and IPv6.
 *
 * Returns true when the session must be reset and closed by its owning engine.
 */
internal object TcpSniSecurityInspector {
    fun inspectAndShouldBlock(
        service: VpnService,
        session: TcpSession,
        reassembledData: ByteArray,
        ruleEngine: RuleEngine,
        currentNetwork: NetworkKind
    ): Boolean {
        if (reassembledData.isEmpty() || session.state == TcpSession.State.CLOSED) return false

        val result = TlsSniInspector.feed(session.tlsSniAccumulator, reassembledData) ?: return false
        val sni = result.sni?.takeIf { it.isNotBlank() } ?: return false

        // Threat intelligence is authoritative and cannot be overridden by a
        // custom ALLOW rule. User rules override only the ordinary blocklist.
        val threatMatch = if (ruleEngine.isThreatProtectionEnabled(session.uid, session.packageName)) {
            ThreatSignatureStore.matchDomain(service, sni)
        } else null
        val scopedDomainAllow = threatMatch == null &&
            ConnectionExceptionStore.isDomainAllowed(service, session.uid, sni, session.packageName)
        val customDecision = if (scopedDomainAllow) CustomDomainRuleStore.Action.ALLOW
            else CustomDomainRuleStore.decision(service, sni)
        val customRuleBlocks = when (customDecision) {
            CustomDomainRuleStore.Action.BLOCK -> true
            CustomDomainRuleStore.Action.ALLOW -> false
            null -> null
        }
        val publicBlocklisted = customDecision == null &&
            DomainBlockStore.enabled && DomainBlockStore.isBlocked(sni)
        val bypassOptionalBlocklist = ruleEngine.shouldBypassOptionalDomainFilter(session.uid, session.packageName)
        val sniProtectionEnabled = ruleEngine.isTlsSniProtectionEnabled(session.uid, session.packageName)

        val blocked = DomainEnforcementPolicy.shouldBlockTlsSni(
            threatMatched = threatMatch != null,
            customRuleBlocks = customRuleBlocks,
            publicBlocklisted = publicBlocklisted,
            bypassOptionalBlocklist = bypassOptionalBlocklist,
            sniProtectionEnabled = sniProtectionEnabled
        )

        if (!blocked) {
            if (publicBlocklisted && bypassOptionalBlocklist && threatMatch == null) {
                DiagnosticLogger.logTcpRuntime(
                    session.key, session.uid, session.packageName,
                    "DOMAIN COMPAT BYPASS TLS_SNI=$sni reason=ESSENTIAL"
                )
            }
            return false
        }

        ConnectionHistory.add(
            session.uid,
            session.packageName,
            "TCP",
            currentNetwork,
            formatEndpoint(session.key.srcAddr, session.key.srcPort),
            "$sni:${session.key.dstPort}",
            allowed = false,
            event = "BLOCKED-DOMAIN-SNI",
            reasonCode = when {
                threatMatch != null -> "THREAT_DOMAIN"
                customDecision == CustomDomainRuleStore.Action.BLOCK -> "CUSTOM_DOMAIN_BLOCK"
                else -> "AD_TRACKER_BLOCKLIST"
            },
            reasonDetail = listOfNotNull(
                sni,
                threatMatch?.match?.name,
                threatMatch?.match?.family,
                threatMatch?.match?.source
            ).joinToString(" • ")
        )

        if (threatMatch != null) {
            ThreatSignatureStore.recordNetworkBlock(service)
            SecurityEventStore.record(
                service,
                "THREAT_NETWORK_BLOCK",
                "Threat blocked: ${threatMatch.match.name}",
                "HTTPS SNI $sni • ${threatMatch.match.family ?: "network threat"}",
                threatMatch.match.severity
            )
            NotificationHelper.notifyThreatBlocked(
                service,
                session.packageName,
                sni,
                threatMatch.match.family,
                threatMatch.match.severity
            )
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "THREAT BLOCKED TLS_SNI=$sni source=${threatMatch.match.source}"
            )
        } else {
            val reason = if (customDecision == CustomDomainRuleStore.Action.BLOCK) "CUSTOM_DOMAIN" else "BLOCKLIST"
            DiagnosticLogger.logTcpRuntime(
                session.key, session.uid, session.packageName,
                "DOMAIN BLOCKED TLS_SNI=$sni reason=$reason dst=${session.key.dstAddr.hostAddress ?: "?"}:${session.key.dstPort}"
            )
        }
        return true
    }

    private fun formatEndpoint(address: java.net.InetAddress, port: Int): String {
        val host = address.hostAddress ?: "?"
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
}
