package com.hydra.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter

/**
 * Dynamically-registered receiver (manifest-declared PACKAGE_ADDED/REPLACED
 * receivers are heavily restricted on modern Android, so this is registered
 * for the lifetime of the VPN service instead) that feeds two independent
 * features from the same two system broadcasts:
 *  - QuarantineManager: brand-new installs start blocked until reviewed.
 *  - AppNetworkProfileStore: app updates start a "watch for new destinations" window.
 */
class AppLifecycleWatcher(
    private val context: Context,
    private val quarantineManager: QuarantineManager,
    private val onRulesChanged: () -> Unit
) : BroadcastReceiver() {

    fun register() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED)
            addDataScheme("package")
        }
        context.registerReceiver(this, filter)
    }

    fun unregister() {
        runCatching { context.unregisterReceiver(this) }
    }

    override fun onReceive(ctx: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        if (packageName == ctx.packageName) return
        val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (replacing) {
                    // Handled by ACTION_PACKAGE_REPLACED instead, to avoid double-counting.
                    return
                }
                quarantineManager.onPackageAdded(ctx, packageName)
                onRulesChanged()
                NotificationHelper.notifyQuarantine(ctx, packageName)
            }
            Intent.ACTION_PACKAGE_REPLACED -> {
                AppNetworkProfileStore.onAppUpdated(packageName)
            }
            Intent.ACTION_PACKAGE_FULLY_REMOVED -> {
                quarantineManager.onPackageRemoved(packageName)
                AppNetworkProfileStore.onAppRemoved(packageName)
            }
        }
    }
}
