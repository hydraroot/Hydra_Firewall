package com.hydra.firewall.vpn

import android.content.Context
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.Severity
import com.hydra.firewall.security.ThreatSignatureStore

/**
 * Best-effort HTTP/3/QUIC protection without attempting to decrypt arbitrary
 * QUIC Initial packets. If Hydra recently observed the same app resolving a
 * destination IP, the resolved domain can still be checked against the normal
 * domain policy. Known threat IPs are handled by RuleEngine before this point.
 */
object QuicProtection {
    data class Result(val blocked: Boolean, val reason: String = "", val domain: String? = null, val version: Long = 0L, val cacheable: Boolean = false)

    fun inspect(
        context: Context,
        ruleEngine: RuleEngine,
        uid: Int,
        packageName: String?,
        destination: java.net.InetAddress,
        destinationPort: Int,
        payload: ByteArray
    ): Result {
        if (destinationPort != 443 || !QuicDetector.isLikelyQuicUdp(payload, destinationPort)) return Result(false)
        val info = QuicInspector.inspect(payload)

        // For attributed application UIDs, RuleEngine.evaluateDetailed() has already
        // checked the destination IP threat index immediately before this inspector
        // runs (and rechecks active sessions at the bounded policy cadence). Repeating
        // the same hash-map lookup for every QUIC datagram was redundant. Keep the
        // explicit fallback for INVALID_UID flows, whose RuleEngine precheck can allow
        // traffic before destination-level threat matching when the user opted in.
        if (uid == android.os.Process.INVALID_UID && ruleEngine.isThreatProtectionEnabled(uid, packageName)) {
            val ipThreat = ThreatSignatureStore.matchIp(context, destination.hostAddress?.substringBefore('%') ?: "")
            if (ipThreat != null) {
                ThreatSignatureStore.recordNetworkBlock(context)
                SecurityEventStore.record(context, "THREAT_NETWORK_BLOCK", "Threat blocked: ${ipThreat.match.name}",
                    "QUIC IP ${destination.hostAddress ?: "?"} • ${ipThreat.match.family ?: "network threat"}", ipThreat.match.severity)
                NotificationHelper.notifyThreatBlocked(context, packageName, destination.hostAddress, ipThreat.match.family, ipThreat.match.severity)
                return Result(true, "QUIC_THREAT_IP", null, info.version, cacheable = true)
            }
        }

        // PERSONALIZADO can disable the optional QUIC inspection layer without
        // disabling the independent confirmed-threat protection above.
        if (!ruleEngine.isQuicProtectionEnabled(uid, packageName)) {
            return Result(false, reason = "QUIC_DISABLED", version = info.version, cacheable = true)
        }

        // Do not cache an unknown domain: the DNS-to-IP correlation can arrive
        // after the first UDP packet (or a later QUIC Initial may complete it).
        val domain = DnsIpCorrelationStore.lookup(uid, destination) ?: return Result(false, reason = "NO_DNS_CORRELATION", version = info.version)
        val threat = if (ruleEngine.isThreatProtectionEnabled(uid, packageName)) {
            ThreatSignatureStore.matchDomain(context, domain)
        } else null
        val custom = CustomDomainRuleStore.decision(context, domain)
        val publicBlocklisted = custom == null && DomainBlockStore.enabled && DomainBlockStore.isBlocked(domain)
        val bypassPublicBlocklist = ruleEngine.shouldBypassOptionalDomainFilter(uid, packageName)
        val block = when (custom) {
            CustomDomainRuleStore.Action.BLOCK -> true
            CustomDomainRuleStore.Action.ALLOW -> false
            null -> publicBlocklisted && !bypassPublicBlocklist
        }
        if (publicBlocklisted && bypassPublicBlocklist && threat == null) {
            DiagnosticLogger.logServiceEvent(
                "DOMAIN COMPAT BYPASS QUIC domain=$domain uid=$uid pkg=${packageName ?: "unknown"} reason=ESSENTIAL"
            )
        }
        if (!block && threat == null) return Result(false, domain = domain, version = info.version, cacheable = true)
        val reason = when {
            threat != null -> "QUIC_THREAT_DOMAIN"
            custom == CustomDomainRuleStore.Action.BLOCK -> "QUIC_CUSTOM_DOMAIN"
            else -> "QUIC_BLOCKLIST_DOMAIN"
        }
        if (threat != null) {
            ThreatSignatureStore.recordNetworkBlock(context)
            SecurityEventStore.record(
                context,
                "THREAT_NETWORK_BLOCK",
                "Threat blocked: ${threat.match.name}",
                "QUIC ${domain} • ${threat.match.family ?: "network threat"}",
                threat.match.severity
            )
            NotificationHelper.notifyThreatBlocked(
                context, packageName, domain, threat.match.family, threat.match.severity
            )
        } else {
            SecurityEventStore.record(
                context,
                "DOMAIN_BLOCK",
                "QUIC domain blocked",
                "$domain • $reason",
                Severity.INFO
            )
        }
        return Result(true, reason, domain, info.version, cacheable = true)
    }
}
