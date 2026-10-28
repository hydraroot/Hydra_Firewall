package com.hydra.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.UserManager
import androidx.core.content.ContextCompat
import com.hydra.firewall.security.ThreatSignatureUpdater

/** Restores the user's requested VPN state after reboot/package replacement/unlock. */
class BootReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION_THREAT_UPDATE = "com.hydra.firewall.action.THREAT_UPDATE"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == ACTION_THREAT_UPDATE) {
            ThreatSignatureUpdater.updateIfDue(context, force = true)
            ThreatSignatureUpdater.scheduleDaily(context)
            return
        }
        if (action == VpnRecoveryScheduler.ACTION_RECOVER) {
            recoverVpn(context, "ALARM_RECOVERY")
            return
        }
        if (action == VpnRecoveryScheduler.ACTION_HEALTH_CHECK) {
            val wantsRunning = context.getSharedPreferences("firewall_service", Context.MODE_PRIVATE)
                .getBoolean("desired_running", false)
            if (wantsRunning && !FirewallVpnService.isRunning) {
                recoverVpn(context, "HEALTH_CHECK")
            } else if (wantsRunning) {
                VpnRecoveryScheduler.scheduleHealthCheck(context)
            }
            return
        }
        if (action == Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            // Direct-Boot aware entry point: do not start the full VPN while the
            // credential-protected rules/configuration may still be unavailable.
            val dps = context.createDeviceProtectedStorageContext()
            val wantsRunning = dps.getSharedPreferences("firewall_service_device", Context.MODE_PRIVATE)
                .getBoolean("desired_running", false)
            DirectBootState.markLockedBoot(dps)
            if (wantsRunning) {
                DiagnosticLogger.init(dps)
                DiagnosticLogger.logServiceEvent("DIRECT_BOOT_DETECTED_RECOVERY_QUEUED")
            }
            return
        }
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED &&
            action != Intent.ACTION_USER_UNLOCKED) return

        ThreatSignatureUpdater.scheduleDaily(context)
        if (action == Intent.ACTION_USER_UNLOCKED) DirectBootState.markUnlocked(context)
        recoverVpn(context, action)
    }

    private fun recoverVpn(context: Context, reason: String) {
        val prefs = context.getSharedPreferences("firewall_service", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("desired_running", false)) {
            VpnRecoveryScheduler.cancel(context)
            return
        }
        val serviceIntent = Intent(context, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(context, serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
        DiagnosticLogger.init(context)
        DiagnosticLogger.logServiceEvent("VPN_RECOVERY_REQUESTED reason=$reason")
    }
}
