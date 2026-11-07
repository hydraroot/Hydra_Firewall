package com.hydra.firewall.vpn

import android.content.Context
import android.os.Build
import com.hydra.firewall.AppSettings
import com.hydra.firewall.BuildConfig
import com.hydra.firewall.security.SecurityEventStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Plain-text report the user can paste into a bug report. It never contains destinations, domains, IP addresses or
 * connection history: only versions, switches and the titles of the latest security events.
 */
object DiagnosticsReport {
    fun build(context: Context): String {
        val app = context.applicationContext
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val settings = AppSettings(app)
        val service = app.getSharedPreferences("firewall_service", Context.MODE_PRIVATE)
        val list = runCatching { DomainBlockStore.activeListInfo() }.getOrNull()
        val sb = StringBuilder()
        sb.appendLine("Hydra Firewall diagnostic report")
        sb.appendLine("Generated: ${fmt.format(Date())}")
        sb.appendLine("App: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        sb.appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("Mode: ${if (settings.advancedMode) "Advanced" else "Normal"} · Language: ${settings.language}")
        sb.appendLine("Firewall running: ${FirewallVpnService.isRunning} · wants running: ${service.getBoolean("desired_running", false)}")
        sb.appendLine("Paused: ${PauseManager.isPaused(app)}")
        if (list != null) sb.appendLine("Blocklist: ${list.date.ifBlank { "-" }} · ${list.domainCount} domains")
        sb.appendLine()
        sb.appendLine("Latest security events (title only):")
        val events = runCatching { SecurityEventStore.snapshot(app).take(20) }.getOrDefault(emptyList())
        if (events.isEmpty()) sb.appendLine("- none")
        events.forEach { sb.appendLine("- ${fmt.format(Date(it.time))} [${it.severity}] ${it.title}") }
        return sb.toString()
    }
}
