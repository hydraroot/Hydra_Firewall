package com.hydra.firewall.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.hydra.firewall.MainActivity

/**
 * Quick Settings tile. Firewall on -> tap pauses it for 15 min; paused -> tap resumes; off -> tap starts it
 * (or opens the app when the VPN permission is still needed).
 */
class HydraTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        runCatching {
            when {
                // Con el bloqueo por PIN activo, pausar la protección exige abrir la app (que pide el PIN).
                FirewallVpnService.isRunning ->
                    if (isAppLockActive()) openApp() else PauseManager.pause(this, 15)
                PauseManager.isPaused(this) -> if (!PauseManager.resume(this)) openApp()
                else -> startFirewall()
            }
        }.onFailure { openApp() }
        refresh()
    }

    private fun isAppLockActive(): Boolean =
        runCatching { LockStore(this).let { it.enabled && it.configured } }.getOrDefault(true)

    private fun startFirewall() {
        if (VpnService.prepare(this) != null) {
            openApp()
            return
        }
        val intent = Intent(this, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_START }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val paused = PauseManager.isPaused(this)
        val on = FirewallVpnService.isRunning
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Hydra"
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = when {
                on -> "Protegido · tocá para pausar"
                paused -> "En pausa · tocá para reanudar"
                else -> "Apagado · tocá para activar"
            }
        }
        tile.updateTile()
    }
}
