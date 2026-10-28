package com.hydra.firewall.vpn

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

/**
 * Optional automatic permission layer for applications from a user-selected
 * trusted source. It is OFF by default so a fresh installation still asks
 * before allowing ordinary applications.
 *
 * Trusted means either:
 *  - installed by Google Play (installer package com.android.vending), or
 *  - a system/updated-system package signed with the same signing certificate
 *    as the Android platform package.
 *
 * This is only a convenience policy. It is not a malware verdict and explicit
 * user BLOCK rules, schedules, threats and the global kill-switch remain
 * authoritative.
 */
class TrustedAppsStore(private val context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) { prefs.edit().putBoolean(KEY_ENABLED, value).apply() }

    fun isAutoTrusted(uid: Int): Boolean = enabled && TrustedAppsDetector.isTrusted(appContext, uid)

    companion object {
        private const val PREFS = "firewall_settings"
        private const val KEY_ENABLED = "trusted_apps_enabled"
    }
}

object TrustedAppsDetector {
    private const val GOOGLE_PLAY = "com.android.vending"
    private const val ANDROID_PLATFORM = "android"

    fun isTrusted(context: Context, uid: Int): Boolean {
        if (uid < 0) return false
        val pm = context.applicationContext.packageManager
        val packages = runCatching { pm.getPackagesForUid(uid)?.toList().orEmpty() }
            .getOrDefault(emptyList())
        if (packages.isEmpty()) return false

        // A package installed from Google Play is treated as a trusted-source
        // candidate only when Play Store is the recorded installer.
        if (packages.all { pkg ->
                runCatching { pm.getInstallerPackageName(pkg) == GOOGLE_PLAY }.getOrDefault(false)
            }) return true

        // For system components, require both system status and the platform
        // signing certificate. Merely being a system app is not enough.
        val infos = packages.mapNotNull { pkg -> runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() }
        if (infos.size != packages.size) return false
        if (!infos.all { info ->
                (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            }) return false

        val platformSignatures = runCatching {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ANDROID_PLATFORM, PackageManager.GET_SIGNATURES).signatures?.toList().orEmpty()
        }.getOrDefault(emptyList())
        if (platformSignatures.isEmpty()) return false

        return packages.all { pkg ->
            val signatures = runCatching {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.toList().orEmpty()
            }.getOrDefault(emptyList())
            signatures.any { candidate -> platformSignatures.any { it == candidate } }
        }
    }
}
