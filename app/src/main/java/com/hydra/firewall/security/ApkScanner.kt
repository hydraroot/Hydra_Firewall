package com.hydra.firewall.security

import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile

class ApkScanner(private val context: Context) {
    companion object {
        private const val MAX_APK_BYTES = 128L * 1024L * 1024L
        private const val MAX_ZIP_ENTRIES = 50_000
        private const val MAX_DECLARED_UNCOMPRESSED = 512L * 1024L * 1024L
        private const val MAX_SINGLE_ENTRY = 128L * 1024L * 1024L
        private val DEX_NAME = Regex("""classes(\d*)?\.dex""")
        private val NATIVE_HINTS = setOf("frida", "xposed", "substrate", "riru", "zygisk", "magisk", "hook", "inject")
    }

    fun scanUri(uri: Uri, displayName: String? = null): ApkScanReport {
        val sourceName = displayName ?: uri.lastPathSegment ?: "APK"
        val temp = File.createTempFile("hydra_scan_", ".apk", context.cacheDir)
        return try {
            context.contentResolver.openInputStream(uri)?.use { input -> copyLimited(input, temp) }
                ?: return failure(sourceName, "No se pudo abrir el archivo")
            scanFile(temp, sourceName)
        } catch (e: SecurityException) {
            failure(sourceName, e.message ?: "Permiso denegado")
        } catch (e: Exception) {
            failure(sourceName, e.message ?: e.javaClass.simpleName)
        } finally {
            temp.delete()
        }
    }

    fun scanInstalledPackage(packageName: String): ApkScanReport {
        val pm = context.packageManager
        val ai = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
        val path = ai.sourceDir ?: throw IllegalStateException("APK path unavailable")
        val splitFiles = ai.splitSourceDirs?.map(::File).orEmpty().filter { it.isFile && it.canRead() }
        return scanFile(File(path), pm.getApplicationLabel(ai).toString(), splitFiles)
    }

    private fun copyLimited(input: InputStream, target: File) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        target.outputStream().use { output ->
            while (true) {
                val n = input.read(buffer)
                if (n <= 0) break
                total += n
                if (total > MAX_APK_BYTES) throw IllegalArgumentException("APK demasiado grande para análisis local (${MAX_APK_BYTES / (1024 * 1024)} MB)")
                output.write(buffer, 0, n)
            }
        }
    }

    private fun scanFile(file: File, sourceName: String, splitFiles: List<File> = emptyList()): ApkScanReport {
        if (!file.isFile || !file.canRead()) return failure(sourceName, "Archivo no legible")
        if (file.length() > MAX_APK_BYTES) return failure(sourceName, "APK demasiado grande")

        val pm = context.packageManager
        val flags = packageFlags()
        val pi = pm.getPackageArchiveInfo(file.absolutePath, flags)
        val errors = mutableListOf<String>()
        if (pi == null) return failure(sourceName, "Android no pudo interpretar el APK")
        val appInfo = pi.applicationInfo ?: return failure(sourceName, "APK sin información de aplicación")
        appInfo.sourceDir = file.absolutePath
        appInfo.publicSourceDir = file.absolutePath

        val permissions = (pi.requestedPermissions ?: emptyArray()).toList()
        val activities = pi.activities ?: emptyArray()
        val services = pi.services ?: emptyArray()
        val receivers = pi.receivers ?: emptyArray()
        val providers = pi.providers ?: emptyArray()
        val exportedComponents = activities.count(::exported) + services.count(::exported) + receivers.count(::exported) + providers.count(::exported)
        val declaredPermissions = pi.permissions?.associateBy { it.name }.orEmpty()
        fun effectivePermissionStrong(permission: String?): Boolean {
            if (permission.isNullOrBlank()) return false
            val declared = declaredPermissions[permission]
            if (declared != null) {
                return (declared.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE) == android.content.pm.PermissionInfo.PROTECTION_SIGNATURE
            }
            return runCatching {
                val info = pm.getPermissionInfo(permission, 0)
                (info.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE) == android.content.pm.PermissionInfo.PROTECTION_SIGNATURE
            }.getOrDefault(false)
        }
        val exportedUnprotectedActivities = activities.count { it.exported && !effectivePermissionStrong(it.permission) }
        val exportedUnprotectedServices = services.count { it.exported && !effectivePermissionStrong(it.permission) }
        val exportedUnprotectedReceivers = receivers.count { it.exported && !effectivePermissionStrong(it.permission) }
        val exportedUnprotectedProviders = providers.count { it.exported && !effectivePermissionStrong(it.readPermission) && !effectivePermissionStrong(it.writePermission) }
        val exportedUnprotected = exportedUnprotectedActivities + exportedUnprotectedServices + exportedUnprotectedReceivers + exportedUnprotectedProviders
        val exportedUnprotectedNonActivity = exportedUnprotectedServices + exportedUnprotectedReceivers + exportedUnprotectedProviders
        val accessibility = services.count { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
        val deviceAdmin = receivers.count { it.permission == "android.permission.BIND_DEVICE_ADMIN" }
        val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        val canInstall = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions
        val debuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val cleartext = Build.VERSION.SDK_INT >= 23 && (appInfo.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0
        val hasNsc = Build.VERSION.SDK_INT >= 24 && hasNetworkSecurityConfigReference(file)

        var native = 0
        var suspiciousNativeLibraries = 0
        var dex = 0
        var zipEntries = 0
        var declaredUncompressed = 0L
        val splitHashes = linkedSetOf<String>()
        val staticHints = linkedSetOf<String>()
        try {
            ZipFile(file).use { zip ->
                val e = zip.entries()
                while (e.hasMoreElements()) {
                    val entry = e.nextElement()
                    zipEntries++
                    if (zipEntries > MAX_ZIP_ENTRIES) throw IllegalArgumentException("Demasiadas entradas ZIP")
                    val declared = entry.size
                    if (declared > MAX_SINGLE_ENTRY) errors += "Entrada ZIP grande: ${entry.name}"
                    if (declared > 0) {
                        declaredUncompressed += declared
                        if (declaredUncompressed > MAX_DECLARED_UNCOMPRESSED) throw IllegalArgumentException("Tamaño descomprimido declarado excesivo")
                    }
                    if (entry.isDirectory) continue
                    if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) {
                        native++
                        val lower = entry.name.lowercase(Locale.US)
                        if (NATIVE_HINTS.any { lower.contains(it) }) {
                            suspiciousNativeLibraries++
                            staticHints += "native:${entry.name.substringAfterLast('/')}"
                        }
                    }
                    if (DEX_NAME.matches(entry.name)) dex++
                }
            }
        } catch (e: Exception) {
            errors += "ZIP scan: ${e.message ?: e.javaClass.simpleName}"
        }

        // Installed Android apps can consist of a base APK plus split APKs. Audit their ZIP
        // contents too; otherwise code/native libraries placed in a split could be invisible.
        for (split in splitFiles) {
            runCatching {
                if (split.length() <= MAX_APK_BYTES) {
                    splitHashes += sha256(split)
                    ZipFile(split).use { zip ->
                        val e = zip.entries()
                        while (e.hasMoreElements()) {
                            val entry = e.nextElement()
                            if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) {
                                native++
                                val lower = entry.name.lowercase(Locale.US)
                                if (NATIVE_HINTS.any { lower.contains(it) }) {
                                    suspiciousNativeLibraries++
                                    staticHints += "native:${entry.name.substringAfterLast('/')}"
                                }
                            }
                            if (DEX_NAME.matches(entry.name)) dex++
                        }
                    }
                } else {
                    errors += "Split APK demasiado grande: ${split.name}"
                }
            }.onFailure { errors += "Split scan ${split.name}: ${it.message ?: it.javaClass.simpleName}" }
        }

        if (cleartext) staticHints += "usesCleartextTraffic"
        if (hasNsc) staticHints += "networkSecurityConfig"
        if (declaredUncompressed > MAX_DECLARED_UNCOMPRESSED / 2) errors += "El APK declara un tamaño descomprimido elevado"

        val certs = certificateFingerprints(pi, errors)
        val installerPackageName = runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pi.packageName).installingPackageName else null
        }.getOrNull()
        val appFirstInstallTime = runCatching { if (packageNameIsInstalled(pm, pi.packageName)) pm.getPackageInfo(pi.packageName, 0).firstInstallTime else 0L }.getOrDefault(0L)
        val appLastUpdateTime = runCatching { if (packageNameIsInstalled(pm, pi.packageName)) pm.getPackageInfo(pi.packageName, 0).lastUpdateTime else 0L }.getOrDefault(0L)

        val threatMatches = runCatching { ThreatSignatureStore.scanApk(context, file, splitFiles) }
            .getOrElse { errors += "Threat signatures: ${it.message ?: it.javaClass.simpleName}"; emptyList() }
        threatMatches.forEach { match ->
            staticHints += "threat:${match.name}"
        }

        var mh100kAi: Mh100kAiResult? = null
        if (HydraMh100kApkAi.init(context)) {
            runCatching {
                val extraction = Mh100kStaticFeatureExtractor().extract(file, splitFiles, permissions)
                errors += extraction.errors
                if (extraction.extractionIncomplete) {
                    // Absence-mode model features require a complete static inventory.
                    // Unknown/unscanned content must never be treated as feature absence.
                    errors += "MH-100K AI: puntaje omitido porque el análisis estático quedó incompleto"
                } else {
                    val ai = HydraMh100kApkAi.score(extraction.presentFeatureHashes)
                    if (ai != null) {
                        mh100kAi = Mh100kAiResult(
                            score = ai.score,
                            matchedFeatures = ai.matchedFeatures,
                            modelFeatureCount = ai.modelFeatureCount,
                            modelVersion = ai.modelVersion,
                            extractedFeatureCount = extraction.presentFeatureHashes.size,
                            apiCallsObserved = extraction.apiCallsObserved,
                            permissionFeaturesObserved = extraction.permissionFeaturesObserved,
                            intentFeaturesObserved = extraction.intentFeaturesObserved,
                            dexFilesAnalyzed = extraction.dexFilesAnalyzed,
                            extractionIncomplete = false
                        )
                    }
                }
            }.onFailure {
                errors += "MH-100K AI: ${it.message ?: it.javaClass.simpleName}"
            }
        } else {
            errors += "MH-100K AI: modelo no disponible"
        }

        val risk = SecurityRiskEngine.evaluate(
            permissions, exportedComponents, accessibility, deviceAdmin, hasOverlay, canInstall,
            debuggable, native, dex, exportedUnprotected, exportedUnprotectedNonActivity, cleartext, hasNsc,
            suspiciousNativeLibraries, threatMatches
        )
        return ApkScanReport(
            sourceName = sourceName,
            packageName = pi.packageName,
            versionName = pi.versionName,
            versionCode = versionCode(pi),
            sha256 = sha256(file),
            certificateSha256 = certs,
            splitApkSha256 = splitHashes.distinct(),
            permissions = permissions.sorted(),
            activities = activities.size, services = services.size, receivers = receivers.size, providers = providers.size,
            exportedComponents = exportedComponents, exportedUnprotectedNonActivityComponents = exportedUnprotectedNonActivity, accessibilityServices = accessibility, deviceAdminReceivers = deviceAdmin,
            hasOverlayPermission = hasOverlay, canInstallPackages = canInstall, debuggable = debuggable,
            nativeLibraries = native, dexFiles = dex, exportedUnprotectedComponents = exportedUnprotected,
            cleartextTrafficAllowed = cleartext, hasNetworkSecurityConfig = hasNsc,
            installerPackageName = installerPackageName, firstInstallTime = appFirstInstallTime, lastUpdateTime = appLastUpdateTime,
            staticSecurityHints = staticHints.toList(), apkSizeBytes = file.length(), zipEntryCount = zipEntries,
            threatMatches = threatMatches, mh100kAi = mh100kAi, risk = risk, errors = errors
        )
    }

    /**
     * Android does not expose the manifest networkSecurityConfig resource id as a public
     * ApplicationInfo property. We therefore inspect the binary AndroidManifest.xml
     * string table for the attribute name. This is deliberately treated as a static
     * hint, not proof that the configuration is effective.
     */
    private fun hasNetworkSecurityConfigReference(file: File): Boolean {
        return try {
            ZipFile(file).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return false
                val bytes = zip.getInputStream(entry).use { input ->
                    val out = ByteArray(2 * 1024 * 1024)
                    var total = 0
                    while (total < out.size) {
                        val n = input.read(out, total, out.size - total)
                        if (n <= 0) break
                        total += n
                    }
                    if (total == out.size) out else out.copyOf(total)
                }
                val ascii = "networkSecurityConfig".toByteArray(StandardCharsets.US_ASCII)
                val utf16 = "networkSecurityConfig".toByteArray(Charsets.UTF_16LE)
                containsBytes(bytes, ascii) || containsBytes(bytes, utf16)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun packageNameIsInstalled(pm: PackageManager, packageName: String): Boolean = runCatching {
        pm.getApplicationInfo(packageName, 0)
        true
    }.getOrDefault(false)

    private fun packageFlags(): Int {
        var f = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
        f = if (Build.VERSION.SDK_INT >= 28) f or PackageManager.GET_SIGNING_CERTIFICATES else f or PackageManager.GET_SIGNATURES
        return f
    }

    private fun exported(info: ActivityInfo): Boolean = info.exported
    private fun exported(info: ServiceInfo): Boolean = info.exported
    private fun exported(info: ProviderInfo): Boolean = info.exported

    private fun versionCode(pi: PackageInfo): Long = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()

    private fun certificateFingerprints(pi: PackageInfo, errors: MutableList<String>): List<String> {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= 28) {
                val si = pi.signingInfo ?: return emptyList()
                if (si.hasMultipleSigners()) si.apkContentsSigners.toList() else si.signingCertificateHistory.toList()
            } else pi.signatures?.toList().orEmpty()
            signatures.map { sha256(it.toByteArray()) }.distinct()
        } catch (e: Exception) {
            errors += "Firma: ${e.message ?: e.javaClass.simpleName}"
            emptyList()
        }
    }

    private fun sha256(file: File): String = file.inputStream().use { sha256Stream(it) }

    private fun sha256Stream(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buffer)
            if (n <= 0) break
            md.update(buffer, 0, n)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun failure(name: String, error: String): ApkScanReport = ApkScanReport(
        sourceName = name, packageName = null, versionName = null, versionCode = null,
        sha256 = "", certificateSha256 = emptyList(), permissions = emptyList(), activities = 0,
        services = 0, receivers = 0, providers = 0, exportedComponents = 0,
        accessibilityServices = 0, deviceAdminReceivers = 0, hasOverlayPermission = false,
        canInstallPackages = false, debuggable = false, nativeLibraries = 0, dexFiles = 0,
        risk = SecurityRisk(0, RiskLevel.SAFE, emptyList()), errors = listOf(error)
    )
}
