package com.hydra.firewall.security

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import com.hydra.firewall.vpn.NotificationHelper

class SecurityEngine(private val context: Context) {
    private val scanner = ApkScanner(context)

    fun scanApk(uri: Uri, displayName: String? = null): ApkScanReport {
        val report = scanner.scanUri(uri, displayName)
        recordReport(report)
        return report
    }

    fun scanInstalledPackage(packageName: String): ApkScanReport {
        var report = scanner.scanInstalledPackage(packageName)
        val observation = BaselineStore.observe(context, report)
        report = report.copy(
            baselineStatus = observation.status,
            baselineChanges = observation.changes
        )
        recordReport(report)
        if (observation.status == BaselineStatus.FIRST_SEEN) {
            SecurityEventStore.record(
                context, "BASELINE_CREATED", "Baseline created: $packageName",
                "First known security baseline was stored for this installed app.", Severity.INFO
            )
        } else if (observation.status == BaselineStatus.CHANGED) {
            SecurityEventStore.record(
                context, "BASELINE_CHANGED", "Security baseline changed: $packageName",
                observation.changes.joinToString("; ").take(3500), Severity.HIGH
            )
        }
        return report
    }

    fun acceptBaseline(report: ApkScanReport): Boolean = BaselineStore.acceptReport(context, report)

    private fun recordReport(report: ApkScanReport) {
        val title = "APK scanned: ${report.packageName ?: report.sourceName}"
        val aiDetail = report.mh100kAi?.let { " • MH-100K ${it.score}/100 (secondary)" }.orEmpty()
        val detail = "${report.risk.level} ${report.risk.score}/100 • SHA-256 ${report.sha256.take(16)}$aiDetail"
        SecurityEventStore.record(context, "APK_SCAN", title, detail, severity(report.risk.level))
        if (report.threatMatches.isNotEmpty()) {
            val names = report.threatMatches.take(5).joinToString(", ") { it.name }
            val maxThreat = report.threatMatches.maxByOrNull { it.severity.ordinal }!!
            SecurityEventStore.record(
                context,
                "THREAT_SIGNATURE_MATCH",
                "Threat signature match",
                "${report.packageName ?: report.sourceName} • $names",
                maxThreat.severity
            )
            NotificationHelper.notifyThreatBlocked(
                context, report.packageName, report.sha256, maxThreat.family ?: maxThreat.name, maxThreat.severity
            )
        }
    }

    fun severity(level: RiskLevel): Severity = when (level) {
        RiskLevel.SAFE -> Severity.INFO
        RiskLevel.LOW -> Severity.LOW
        RiskLevel.MEDIUM -> Severity.MEDIUM
        RiskLevel.HIGH -> Severity.HIGH
        RiskLevel.CRITICAL -> Severity.CRITICAL
    }
}

object BaselineStore {
    private const val PREFS = "hydra_security_baseline"
    private const val KEY = "apps"

    data class Baseline(
        val packageName: String,
        val versionCode: Long,
        val versionName: String?,
        val sha256: String,
        val certs: List<String>,
        val permissionsHash: String,
        val exported: Int,
        val exportedNonActivity: Int,
        val cleartext: Boolean,
        val nsc: Boolean,
        val installer: String?,
        val splitHashes: List<String>,
        val updatedAt: Long
    )

    data class Observation(val status: BaselineStatus, val changes: List<String>)

    fun observe(context: Context, report: ApkScanReport): Observation {
        val pkg = report.packageName ?: return Observation(BaselineStatus.NOT_APPLICABLE, emptyList())
        val current = fingerprint(report)
        val previous = get(context, pkg)
        if (previous == null) {
            save(context, current)
            return Observation(BaselineStatus.FIRST_SEEN, listOf("baseline inicial"))
        }
        val changes = mutableListOf<String>()
        if (previous.sha256 != current.sha256) changes += "SHA-256 cambió"
        if (previous.certs != current.certs) changes += "certificado/firma cambió"
        if (previous.versionCode != current.versionCode) changes += "versionCode cambió (${previous.versionCode}→${current.versionCode})"
        if (previous.permissionsHash != current.permissionsHash) changes += "permisos cambiaron"
        if (previous.splitHashes != current.splitHashes) changes += "splits APK cambiaron"
        if (previous.exportedNonActivity != current.exportedNonActivity) changes += "componentes exportados no-Activity cambiaron"
        if (previous.cleartext != current.cleartext) changes += "política cleartext cambió"
        if (previous.nsc != current.nsc) changes += "Network Security Config cambió"
        if (previous.installer != current.installer) changes += "instalador/origen cambió"
        return if (changes.isEmpty()) Observation(BaselineStatus.UNCHANGED, emptyList())
        else Observation(BaselineStatus.CHANGED, changes)
    }

    fun acceptReport(context: Context, report: ApkScanReport): Boolean {
        return runCatching {
            val packageName = report.packageName ?: return false
            save(context, fingerprint(report))
            SecurityEventStore.record(context, "BASELINE_ACCEPTED", "Baseline updated: $packageName", "Current analyzed state was explicitly accepted as the new baseline.", Severity.INFO)
            true
        }.getOrDefault(false)
    }

    private fun fingerprint(report: ApkScanReport): Baseline {
        val ph = java.security.MessageDigest.getInstance("SHA-256")
            .digest(report.permissions.sorted().joinToString("\n").toByteArray())
            .joinToString("") { "%02x".format(it) }
        return Baseline(
            report.packageName!!,
            report.versionCode ?: 0L,
            report.versionName,
            report.sha256,
            report.certificateSha256,
            ph,
            report.exportedComponents,
            report.exportedUnprotectedNonActivityComponents,
            report.cleartextTrafficAllowed,
            report.hasNetworkSecurityConfig,
            report.installerPackageName,
            report.splitApkSha256,
            System.currentTimeMillis()
        )
    }

    private fun save(context: Context, baseline: Baseline) {
        val current = all(context).associateBy { it.packageName }.toMutableMap()
        current[baseline.packageName] = baseline
        val a = JSONArray()
        current.values.take(500).forEach { b ->
            a.put(JSONObject().apply {
                put("package", b.packageName)
                put("versionCode", b.versionCode)
                put("versionName", b.versionName)
                put("sha256", b.sha256)
                put("certs", JSONArray(b.certs))
                put("permissionsHash", b.permissionsHash)
                put("splitHashes", JSONArray(b.splitHashes))
                put("exported", b.exported)
                put("exportedNonActivity", b.exportedNonActivity)
                put("cleartext", b.cleartext)
                put("nsc", b.nsc)
                if (b.installer != null) put("installer", b.installer)
                put("updatedAt", b.updatedAt)
            })
        }
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, a.toString()).apply()
    }

    fun get(context: Context, packageName: String): Baseline? = all(context).firstOrNull { it.packageName == packageName }

    fun all(context: Context): List<Baseline> {
        val raw = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "[]") ?: "[]"
        return runCatching {
            val a = JSONArray(raw)
            buildList {
                for (i in 0 until a.length()) {
                    val o = a.getJSONObject(i)
                    add(
                        Baseline(
                            packageName = o.getString("package"),
                            versionCode = o.optLong("versionCode"),
                            versionName = o.optString("versionName", null),
                            sha256 = o.optString("sha256"),
                            certs = o.optJSONArray("certs")?.let { arr -> (0 until arr.length()).map { j -> arr.getString(j) } }.orEmpty(),
                            permissionsHash = o.optString("permissionsHash"),
                            exported = o.optInt("exported"),
                            exportedNonActivity = o.optInt("exportedNonActivity", o.optInt("exported")),
                            cleartext = o.optBoolean("cleartext", false),
                            nsc = o.optBoolean("nsc", false),
                            installer = o.optString("installer", null),
                            splitHashes = o.optJSONArray("splitHashes")?.let { arr -> (0 until arr.length()).map { j -> arr.getString(j) } }.orEmpty(),
                            updatedAt = o.optLong("updatedAt")
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }
}
