package com.hydra.firewall.security

data class SecurityIndicator(
    val code: String,
    val title: String,
    val detail: String,
    val severity: Severity,
    val points: Int
)

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

data class SecurityRisk(
    val score: Int,
    val level: RiskLevel,
    val indicators: List<SecurityIndicator>
)

enum class RiskLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL }

data class Mh100kAiResult(
    val score: Int,
    val matchedFeatures: Int,
    val modelFeatureCount: Int,
    val modelVersion: String,
    val extractedFeatureCount: Int,
    val apiCallsObserved: Int,
    val permissionFeaturesObserved: Int,
    val intentFeaturesObserved: Int,
    val dexFilesAnalyzed: Int,
    val extractionIncomplete: Boolean
)

data class ApkScanReport(
    val sourceName: String,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val sha256: String,
    val certificateSha256: List<String>,
    val splitApkSha256: List<String> = emptyList(),
    val permissions: List<String>,
    val activities: Int,
    val services: Int,
    val receivers: Int,
    val providers: Int,
    val exportedComponents: Int,
    val accessibilityServices: Int,
    val deviceAdminReceivers: Int,
    val hasOverlayPermission: Boolean,
    val canInstallPackages: Boolean,
    val debuggable: Boolean,
    val nativeLibraries: Int,
    val dexFiles: Int,
    val exportedUnprotectedComponents: Int = 0,
    val exportedUnprotectedNonActivityComponents: Int = 0,
    val cleartextTrafficAllowed: Boolean = false,
    val hasNetworkSecurityConfig: Boolean = false,
    val webViewReferences: Int = 0,
    val javascriptInterfaceReferences: Int = 0,
    val suspiciousUrlReferences: Int = 0,
    val installerPackageName: String? = null,
    val firstInstallTime: Long = 0L,
    val lastUpdateTime: Long = 0L,
    val baselineStatus: BaselineStatus = BaselineStatus.NOT_APPLICABLE,
    val baselineChanges: List<String> = emptyList(),
    val staticSecurityHints: List<String> = emptyList(),
    val apkSizeBytes: Long = 0L,
    val zipEntryCount: Int = 0,
    val threatMatches: List<ThreatSignatureMatch> = emptyList(),
    val mh100kAi: Mh100kAiResult? = null,
    val risk: SecurityRisk,
    val errors: List<String> = emptyList()
)


enum class BaselineStatus { NOT_APPLICABLE, FIRST_SEEN, UNCHANGED, CHANGED }
