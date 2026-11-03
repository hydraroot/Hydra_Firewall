package com.hydra.firewall.security

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import com.hydra.firewall.vpn.NotificationHelper

/** Receives the PackageInstaller result of a Hydra self-update. */
class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val version = intent.getStringExtra("version").orEmpty()
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // Android needs the user's confirmation (or the "install unknown apps" permission).
                @Suppress("DEPRECATION")
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                AppUpdater.setPhase(AppUpdater.Phase.CONFIRM)
                AppUpdater.setMessage(context, "CONFIRM:$version")
                NotificationHelper.notifyAppUpdate(context, version, readyToInstall = true, confirmIntent = confirm)
                runCatching { context.startActivity(confirm) }
            }
            PackageInstaller.STATUS_SUCCESS -> { AppUpdater.setPhase(AppUpdater.Phase.IDLE); AppUpdater.setMessage(context, "UP_TO_DATE") }
            else -> {
                AppUpdater.setPhase(AppUpdater.Phase.IDLE)
                AppUpdater.setMessage(
                    context, "ERROR:install_" + (intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: status.toString())
                )
            }
        }
    }
}
