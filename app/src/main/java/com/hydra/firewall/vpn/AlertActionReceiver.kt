package com.hydra.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Botones de la notificación de aviso: Bloquear / Dejar / Deshacer. No exportado. */
class AlertActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val id = intent.getLongExtra(EXTRA_ID, -1L)
        if (id < 0) return
        when (intent.action) {
            ACTION_BLOCK -> {
                val a = AlertStore.block(context, id) ?: return
                notifyRules(context)
                NotificationHelper.notifyBlockUndo(context, a)
            }
            ACTION_UNDO -> {
                AlertStore.unblock(context, id, AlertStore.Status.PENDING)
                notifyRules(context)
                NotificationHelper.cancelBlockAlert(context, id)
            }
            ACTION_DISMISS -> {
                AlertStore.ignore(context, id)
                NotificationHelper.cancelBlockAlert(context, id)
            }
        }
    }

    private fun notifyRules(context: Context) {
        if (!FirewallVpnService.isRunning) return
        context.startService(Intent(context, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED })
    }

    companion object {
        const val ACTION_BLOCK = "com.hydra.firewall.action.ALERT_BLOCK"
        const val ACTION_UNDO = "com.hydra.firewall.action.ALERT_UNDO"
        const val ACTION_DISMISS = "com.hydra.firewall.action.ALERT_DISMISS"
        const val EXTRA_ID = "alert_id"
    }
}
