package com.hydra.firewall.security

data class ThreatSignatureMatch(
    val kind: Kind,
    val name: String,
    val family: String?,
    val source: String,
    val severity: Severity,
    val confidence: Int,
    val detail: String
) {
    enum class Kind { SHA256, YARA, DOMAIN, IP, URL }
}

data class ThreatSignatureStatus(
    val enabled: Boolean,
    val packVersion: String,
    val generatedAt: Long,
    val expiresAt: Long,
    val sha256Count: Int,
    val domainCount: Int,
    val ipCount: Int,
    val urlCount: Int,
    val yaraRuleCount: Int,
    val liveThreatDomainCount: Int = 0,
    val liveThreatSource: String = "",
    val sourceSummary: List<String>,
    val lastUpdateError: String?
)
