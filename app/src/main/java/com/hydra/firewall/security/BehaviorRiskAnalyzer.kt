package com.hydra.firewall.security

import com.hydra.firewall.vpn.ConnectionHistory
import com.hydra.firewall.vpn.TrafficAnalyzerStore

object BehaviorRiskAnalyzer {
    data class AppBehavior(
        val packageName: String,
        val connections: Int,
        val uniqueDestinations: Int,
        val dnsQueries: Int,
        val dnsBlocks: Int,
        val unusualPorts: Int,
        val score: Int,
        val level: RiskLevel,
        val recentConnections: Int = 0,
        val newDestinations: Int = 0,
        val aiScore: Int? = null,
        val aiLevel: RiskLevel? = null,
        val aiExplanation: String? = null,
        val privacyScore: Int? = null,
        val privacyLevel: RiskLevel? = null,
        val privacyExplanation: String? = null
    )

    fun analyze(events: List<TrafficAnalyzerStore.Event>): List<AppBehavior> {
        val grouped = events.groupBy { it.packageName ?: "uid:${it.uid}" }
        val now = System.currentTimeMillis()
        val history = ConnectionHistory.snapshot()
        val recentWindow = 15 * 60 * 1000L
        return grouped.map { (pkg, list) ->
            val dest = list.map { it.destination.lowercase() }.toSet().size
            val dns = list.count { it.protocol == "DNS" }
            val dnsBlocks = list.count { it.kind == "DNS_BLOCK" }
            val unusual = list.count { isUnusualPort(it.port) }
            val sniBlocks = history.count {
                (it.packageName ?: "uid:${it.uid}") == pkg &&
                    it.event == "BLOCKED-DOMAIN-SNI" &&
                    !it.allowed
            }
            val recent = list.count { val age = now - it.timestamp; age in 0..recentWindow }
            val old = list.filter { val age = now - it.timestamp; age > recentWindow }.map { it.destination.lowercase() }.toSet()
            val recentDest = list.filter { val age = now - it.timestamp; age in 0..recentWindow }.map { it.destination.lowercase() }.toSet()
            val newDestinations = recentDest.count { it !in old }

            // Volume is logarithmic rather than integer division so 1..9 connections
            // are not all scored as zero and large bursts do not dominate the result.
            val volumePoints = when { list.size >= 500 -> 8; list.size >= 100 -> 5; list.size >= 25 -> 3; else -> 0 }
            val diversityPoints = when { dest >= 100 -> 6; dest >= 30 -> 4; dest >= 10 -> 2; else -> 0 }
            val unusualPoints = (unusual.coerceAtMost(10) / 3) * 2
            val burstPoints = if (recent >= 100) 4 else if (recent >= 30) 2 else 0
            val score = (volumePoints + diversityPoints + (dnsBlocks.coerceAtMost(4) * 3) + unusualPoints + newDestinations.coerceAtMost(10) + burstPoints).coerceAtMost(100)
            val level = when {
                score >= 70 -> RiskLevel.CRITICAL
                score >= 45 -> RiskLevel.HIGH
                score >= 25 -> RiskLevel.MEDIUM
                score >= 10 -> RiskLevel.LOW
                else -> RiskLevel.SAFE
            }
            val behaviorFeatures = HydraAiEngine.BehaviorFeatures(
                connections = list.size,
                uniqueDestinations = dest,
                dnsQueries = dns,
                dnsBlocks = dnsBlocks,
                tlsAlerts = 0, // el modelo conserva esta entrada; ya no hay huellas TLS
                unusualPorts = unusual,
                recentConnections = recent,
                newDestinations = newDestinations,
                sniBlocks = sniBlocks
            )
            val ai = HydraAiEngine.predict(behaviorFeatures)
            val privacy = HydraPrivacyAiEngine.predict(
                HydraPrivacyAiEngine.Features(
                    connections = list.size,
                    uniqueDestinations = dest,
                    dnsQueries = dns,
                    dnsBlocks = dnsBlocks,
                    recentConnections = recent,
                    newDestinations = newDestinations,
                    sniBlocks = sniBlocks
                )
            )
            AppBehavior(
                packageName = pkg,
                connections = list.size,
                uniqueDestinations = dest,
                dnsQueries = dns,
                dnsBlocks = dnsBlocks,
                unusualPorts = unusual,
                score = score,
                level = level,
                recentConnections = recent,
                newDestinations = newDestinations,
                aiScore = ai?.score,
                aiLevel = ai?.level,
                aiExplanation = ai?.explanation,
                privacyScore = privacy?.score,
                privacyLevel = privacy?.level,
                privacyExplanation = privacy?.explanation
            )
        }.sortedByDescending { it.score }
    }


    private fun isUnusualPort(port: Int): Boolean {
        if (port !in 1..65535) return false
        return port !in setOf(53, 80, 123, 443, 853, 3478, 5349, 5228, 5229, 5223, 8443)
    }
}
