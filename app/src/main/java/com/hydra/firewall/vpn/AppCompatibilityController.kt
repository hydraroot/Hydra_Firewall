package com.hydra.firewall.vpn

import android.content.Context
import android.content.Intent
import android.os.Build

/** Small shared controller used by Rules and the compact access prompt. */
object AppCompatibilityController {
    private const val EXTRA_PACKAGE_NAME = "compat_package_name"
    private const val EXTRA_MODE = "compat_mode"

    fun setModeAndRestart(context: Context, packageName: String, mode: AppCompatibilityMode) {
        val appContext = context.applicationContext
        AppCompatibilityPolicyStore.init(appContext)
        val previousMode = AppCompatibilityPolicyStore.getMode(packageName)
        val uid = runCatching {
            appContext.packageManager.getApplicationInfo(packageName, 0).uid
        }.getOrNull()
        val essentialStore = EssentialAppsStore(appContext)

        // Compatibility modes are mutually exclusive. Keep the compatibility
        // mode and the user-essential flag synchronized so an app can never
        // remain in an in-VPN essential state while it is outside the VPN.
        when (mode) {
            AppCompatibilityMode.EXCLUDED -> uid?.let { essentialStore.setUserEssential(it, false) }
            AppCompatibilityMode.ESSENTIAL,
            AppCompatibilityMode.ESSENTIAL_COMPAT -> uid?.let { essentialStore.setUserEssential(it, true) }
            AppCompatibilityMode.CUSTOM,
            AppCompatibilityMode.NORMAL -> {
                // NORMAL is the explicit state used when leaving SIN FIREWALL
                // or disabling ESENCIAL. Both exceptional modes must be cleared.
                uid?.let { essentialStore.setUserEssential(it, false) }
            }
        }

        // Commit before touching the VPN so the service's next Builder sees the
        // requested mode deterministically.
        AppCompatibilityPolicyStore.setMode(packageName, mode)
        DiagnosticLogger.logServiceEvent(
            "COMPATIBILITY_MODE_SET package=$packageName mode=${mode.name} running=${FirewallVpnService.isRunning}"
        )

        // ESSENTIAL normally stays inside the existing TUN. If we are leaving
        // EXCLUDED, however, the app must be re-added to the VPN, so force the
        // same controlled Builder rebuild used for SIN FIREWALL changes.
        if (mode == AppCompatibilityMode.ESSENTIAL || mode == AppCompatibilityMode.ESSENTIAL_COMPAT) {
            if (previousMode == AppCompatibilityMode.EXCLUDED) {
                // The app was outside the TUN; rebuild the Builder so it is
                // actually re-included before returning to an in-VPN mode.
                if (FirewallVpnService.isRunning) {
                    val intent = Intent(appContext, FirewallVpnService::class.java).apply {
                        action = FirewallVpnService.ACTION_COMPATIBILITY_CHANGED
                        putExtra(EXTRA_PACKAGE_NAME, packageName)
                        putExtra(EXTRA_MODE, mode.name)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) appContext.startForegroundService(intent)
                    else appContext.startService(intent)
                }
            } else if (FirewallVpnService.isRunning) {
                // Same TUN; only packet-time policy changes are needed.
                appContext.startService(Intent(appContext, FirewallVpnService::class.java).apply {
                    action = FirewallVpnService.ACTION_RULES_CHANGED
                })
            }
            return
        }

        // EXCLUDED/NORMAL changes the Builder's disallowed-app list. Let the
        // service perform a controlled in-place restart, just like live-test
        // mode, instead of stopping the service and racing a delayed START.
        if (!FirewallVpnService.isRunning) return

        val intent = Intent(appContext, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_COMPATIBILITY_CHANGED
            putExtra(EXTRA_PACKAGE_NAME, packageName)
            putExtra(EXTRA_MODE, mode.name)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
    }

    fun packageExtraKey(): String = EXTRA_PACKAGE_NAME
    fun modeExtraKey(): String = EXTRA_MODE
}
