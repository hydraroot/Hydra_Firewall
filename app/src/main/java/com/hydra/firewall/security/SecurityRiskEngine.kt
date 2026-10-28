package com.hydra.firewall.security

object SecurityRiskEngine {
    fun evaluate(
        permissions: List<String>,
        exportedComponents: Int,
        accessibilityServices: Int,
        deviceAdminReceivers: Int,
        hasOverlayPermission: Boolean,
        canInstallPackages: Boolean,
        debuggable: Boolean,
        nativeLibraries: Int,
        dexFiles: Int,
        exportedUnprotectedComponents: Int = 0,
        exportedUnprotectedNonActivityComponents: Int = exportedUnprotectedComponents,
        cleartextTrafficAllowed: Boolean = false,
        hasNetworkSecurityConfig: Boolean = false,
        webViewReferences: Int = 0,
        javascriptInterfaceReferences: Int = 0,
        suspiciousUrlReferences: Int = 0,
        suspiciousNativeLibraries: Int = 0,
        threatMatches: List<ThreatSignatureMatch> = emptyList()
    ): SecurityRisk {
        val out = mutableListOf<SecurityIndicator>()
        fun add(code: String, title: String, detail: String, severity: Severity, points: Int) {
            out += SecurityIndicator(code, title, detail, severity, points)
        }

        val p = permissions.toSet()
        if (accessibilityServices > 0) add("ACCESSIBILITY", "Accessibility service", "Can receive accessibility events and interact with UI.", Severity.HIGH, 25)
        if (deviceAdminReceivers > 0) add("DEVICE_ADMIN", "Device administrator", "Declares a device-admin receiver.", Severity.HIGH, 25)
        if (hasOverlayPermission || "android.permission.SYSTEM_ALERT_WINDOW" in p) add("OVERLAY", "Overlay capability", "Can request drawing over other apps.", Severity.MEDIUM, 12)
        if (canInstallPackages || "android.permission.REQUEST_INSTALL_PACKAGES" in p) add("INSTALL_PACKAGES", "Package installation", "Can request installation of other packages.", Severity.HIGH, 18)
        if ("android.permission.RECORD_AUDIO" in p) add("MIC", "Microphone", "Requests microphone access.", Severity.MEDIUM, 5)
        if ("android.permission.CAMERA" in p) add("CAMERA", "Camera", "Requests camera access.", Severity.MEDIUM, 4)
        if ("android.permission.READ_SMS" in p || "android.permission.RECEIVE_SMS" in p || "android.permission.SEND_SMS" in p) add("SMS", "SMS access", "Requests SMS access.", Severity.HIGH, 15)
        if ("android.permission.READ_CONTACTS" in p || "android.permission.WRITE_CONTACTS" in p) add("CONTACTS", "Contacts", "Requests contacts access.", Severity.MEDIUM, 6)
        if ("android.permission.READ_CALL_LOG" in p || "android.permission.WRITE_CALL_LOG" in p || "android.permission.CALL_PHONE" in p) add("CALLS", "Call access", "Requests call-related permissions.", Severity.HIGH, 12)
        if ("android.permission.ACCESS_FINE_LOCATION" in p || "android.permission.ACCESS_COARSE_LOCATION" in p) add("LOCATION", "Location", "Requests location access.", Severity.MEDIUM, 5)
        if ("android.permission.REQUEST_DELETE_PACKAGES" in p) add("DELETE_PACKAGES", "Package removal", "Can request deletion of packages.", Severity.HIGH, 12)
        if ("android.permission.QUERY_ALL_PACKAGES" in p) add("QUERY_APPS", "App inventory", "Can query installed applications broadly.", Severity.LOW, 2)
        if ("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in p) add("BATTERY_BYPASS", "Battery optimization exemption", "Can request exemption from battery optimization; review persistence implications.", Severity.MEDIUM, 4)
        if ("android.permission.MANAGE_EXTERNAL_STORAGE" in p) add("MANAGE_STORAGE", "Broad storage access", "Requests broad file-system access.", Severity.HIGH, 12)
        if ("android.permission.PACKAGE_USAGE_STATS" in p) add("USAGE_STATS", "Usage statistics", "Can request broad app-usage visibility.", Severity.MEDIUM, 4)
        if ("android.permission.WRITE_SETTINGS" in p) add("WRITE_SETTINGS", "System settings", "Can request permission to modify system settings.", Severity.HIGH, 8)
        if ("android.permission.RECEIVE_BOOT_COMPLETED" in p) add("BOOT", "Boot receiver capability", "Can receive boot completion and potentially start work after reboot.", Severity.LOW, 1)
        if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in p) add("NOTIFICATION_LISTENER", "Notification listener", "Can receive notifications and potentially sensitive notification content.", Severity.HIGH, 18)
        if (debuggable) add("DEBUGGABLE", "Debuggable build", "Application is marked debuggable.", Severity.MEDIUM, 10)
        if (exportedComponents > 8) add("EXPORTED", "Many exported components", "$exportedComponents components are exported.".replace("$exportedComponents", exportedComponents.toString()), Severity.MEDIUM, 4)

        // Launcher activities are commonly exported by design. Score exported activities
        // less aggressively; focus the security signal on services/receivers/providers that
        // are exported without an effective permission.
        if (exportedUnprotectedNonActivityComponents > 0) {
            add(
                "EXPORTED_UNPROTECTED",
                "Exported non-activity components without permission",
                "$exportedUnprotectedNonActivityComponents exported services/receivers/providers do not declare an effective protection permission.",
                Severity.HIGH,
                exportedUnprotectedNonActivityComponents.coerceAtMost(5) * 6
            )
        }
        if (cleartextTrafficAllowed) add("CLEARTEXT", "Cleartext traffic allowed", "The application permits HTTP/other cleartext traffic.", Severity.MEDIUM, 8)
        if (hasNetworkSecurityConfig) add("NSC", "Network security configuration", "A custom Network Security Configuration is present and should be reviewed.", Severity.INFO, 0)
        if (webViewReferences > 0) add("WEBVIEW", "WebView detected", "$webViewReferences static WebView references were found.", Severity.LOW, 1)
        if (javascriptInterfaceReferences > 0) add("JS_BRIDGE", "JavaScript interface reference", "$javascriptInterfaceReferences static addJavascriptInterface references were found; review WebView bridges.", Severity.HIGH, 10)
        if (suspiciousUrlReferences > 0) add("URLS", "Embedded network endpoints", "$suspiciousUrlReferences static URL/reference strings were found.", Severity.LOW, 1)
        if (nativeLibraries > 0) add("NATIVE", "Native code", "$nativeLibraries native-library entries found.", Severity.LOW, 1)
        if (suspiciousNativeLibraries > 0) add("NATIVE_HINT", "Native library security hints", "$suspiciousNativeLibraries native library names matched a security-sensitive heuristic and require review.", Severity.MEDIUM, suspiciousNativeLibraries.coerceAtMost(4) * 2)
        if (dexFiles > 3) add("DEX", "Many DEX files", "$dexFiles DEX files found.", Severity.LOW, 1)
        if (threatMatches.isNotEmpty()) {
            val maxPoints = threatMatches.maxOf {
                when (it.severity) {
                    Severity.CRITICAL -> 70
                    Severity.HIGH -> 45
                    Severity.MEDIUM -> 20
                    Severity.LOW -> 8
                    Severity.INFO -> 0
                }
            }
            val families = threatMatches.mapNotNull { it.family }.distinct().take(3).joinToString(", ")
            add(
                "THREAT_SIGNATURE",
                "Threat signature match",
                "Matched ${threatMatches.size} local threat signature(s)${if (families.isBlank()) "" else ": $families"}.",
                threatMatches.maxBy { severityRank(it.severity) }.severity,
                maxPoints
            )
        }


        if (accessibilityServices > 0 && hasOverlayPermission && canInstallPackages)
            add("ACCESS_TRIPLE", "High-impact capability combination", "Accessibility + overlay + package installation is a materially stronger indicator than any single capability.", Severity.CRITICAL, 25)
        else if (accessibilityServices > 0 && (hasOverlayPermission || canInstallPackages))
            add("ACCESS_COMBO", "High-impact capability combination", "Accessibility combined with overlay/package-install capability deserves review.", Severity.HIGH, 12)
        if (deviceAdminReceivers > 0 && canInstallPackages)
            add("ADMIN_INSTALL_COMBO", "Admin + installer", "Device-admin and package-install capabilities are combined.", Severity.CRITICAL, 20)
        if (nativeLibraries > 0 && debuggable)
            add("NATIVE_DEBUG_COMBO", "Native + debuggable", "Native code is present in a debuggable package.", Severity.MEDIUM, 4)
        if (javascriptInterfaceReferences > 0 && cleartextTrafficAllowed)
            add("WEBVIEW_CLEARTEXT", "WebView + cleartext", "A JavaScript bridge reference appears together with cleartext traffic capability.", Severity.HIGH, 10)
        if (exportedUnprotectedNonActivityComponents > 0 && javascriptInterfaceReferences > 0)
            add("IPC_WEBVIEW_COMBO", "Exported IPC + WebView bridge", "Exported non-activity components and JavaScript bridges together warrant manual review.", Severity.HIGH, 8)

        val score = out.sumOf { it.points }.coerceAtMost(100)
        val level = when {
            score >= 70 -> RiskLevel.CRITICAL
            score >= 45 -> RiskLevel.HIGH
            score >= 25 -> RiskLevel.MEDIUM
            score >= 10 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
        return SecurityRisk(score, level, out.sortedWith(compareByDescending<SecurityIndicator> { it.points }.thenBy { it.code }))
    }

    private fun severityRank(severity: Severity): Int = when (severity) {
        Severity.INFO -> 0
        Severity.LOW -> 1
        Severity.MEDIUM -> 2
        Severity.HIGH -> 3
        Severity.CRITICAL -> 4
    }
}
