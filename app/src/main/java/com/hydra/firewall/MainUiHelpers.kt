package com.hydra.firewall

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import com.hydra.firewall.vpn.*
import java.util.Locale

@Composable
internal fun hydraDialogColors(): Triple<Color, Color, Color> = Triple(
    MaterialTheme.colorScheme.surface,
    MaterialTheme.colorScheme.onSurface,
    MaterialTheme.colorScheme.onSurfaceVariant
)

internal fun historySortLabel(context: Context, sort: HistorySort): String = when (sort) {
    HistorySort.TIME -> tr(context, "sort_time")
    HistorySort.APP -> tr(context, "sort_app")
    HistorySort.IP -> tr(context, "sort_ip")
    HistorySort.PORT -> tr(context, "sort_port")
}

internal fun extractHost(address: String): String {
    val value = address.trim()
    if (value.startsWith("[")) {
        val end = value.indexOf(']')
        if (end > 1) return value.substring(1, end)
    }
    val colon = value.lastIndexOf(':')
    return if (colon > 0 && value.substring(colon + 1).toIntOrNull() != null) value.substring(0, colon) else value
}

internal fun extractPort(address: String): Int {
    val value = address.trim()
    val port = value.substringAfterLast(':', "")
    return port.toIntOrNull() ?: -1
}

/** Extract only a normalized domain explicitly stored in the historical decision detail. */
internal fun extractDecisionDomain(record: ConnectionHistory.Record): String? {
    val candidates = buildList {
        record.reasonDetail?.split('•')?.forEach { add(it.trim()) }
        add(extractHost(record.destination))
    }
    return candidates.firstNotNullOfOrNull { com.hydra.firewall.vpn.CustomDomainRuleStore.normalize(it) }
}

internal fun serviceLabelForPort(port: Int): String = when (port) {
    53 -> "DNS"
    80 -> "HTTP"
    443 -> "HTTPS"
    853 -> "DoT"
    1900 -> "SSDP"
    3478, 3479 -> "STUN"
    5228, 5229, 5230 -> "Google"
    123 -> "NTP"
    else -> "TCP/UDP"
}

internal fun serviceLabel(destination: String): String = serviceLabelForPort(extractPort(destination))

internal fun startActivitySafe(context: Context, action: String) { runCatching { context.startActivity(Intent(action)) } }

internal data class SystemAppSafety(
    val labelEs: String,
    val labelEn: String,
    val detailEs: String,
    val detailEn: String,
    val color: Color
)

internal fun systemAppSafety(packageName: String): SystemAppSafety {
    val p = packageName.lowercase()
    val critical = setOf(
        "com.android.systemui", "com.android.settings", "com.android.phone",
        "com.android.providers.telephony", "com.android.providers.settings",
        "com.android.packageinstaller", "com.android.permissioncontroller",
        "com.google.android.gms", "com.google.android.gsf"
    )
    if (p in critical) return SystemAppSafety(
        "ALTO RIESGO — no se recomienda bloquear", "HIGH RISK — blocking is not recommended",
        "Componente central de Android o servicio ampliamente usado. Bloquear Internet puede romper funciones básicas.",
        "Core Android or widely used Google component. Blocking Internet may break basic functions.",
        Color(0xFFC62828)
    )
    val caution = p.startsWith("com.android.providers.") || p.startsWith("com.android.server.") || p.contains("telephony") || p.contains("connectivity") || p.contains("networkstack")
    if (caution) return SystemAppSafety(
        "PRECAUCIÓN — revisar antes de bloquear", "CAUTION — review before blocking",
        "Parece un proveedor o componente de conectividad del sistema. Su función exacta depende de la versión y del fabricante.",
        "Looks like a system provider or connectivity component. Its exact role depends on Android version and manufacturer.",
        Color(0xFFF57C00)
    )
    return SystemAppSafety(
        "RIESGO NO DETERMINADO — revisar", "UNDETERMINED RISK — review",
        "No se identificó como componente crítico conocido. Esto no garantiza que sea seguro bloquearlo.",
        "Not identified as a known critical component. This does not guarantee that blocking is safe.",
        Color(0xFFF57C00)
    )
}

internal fun themeAccent(theme: AppVisualTheme): Color = when (theme) {
    AppVisualTheme.NEON_TECH -> Color(0xFF00DDF5)
    AppVisualTheme.DARK_PREMIUM -> Color(0xFFC2A7FF)
    AppVisualTheme.LIGHT_MODERN -> Color(0xFF2563EB)
    AppVisualTheme.CYBER_ORANGE -> Color(0xFFFF8A32)
    AppVisualTheme.MATERIAL_MODERN -> Color(0xFFADC6FF)
    AppVisualTheme.GLASS_GREEN -> Color(0xFF59E4AE)
}

internal fun describeAppPolicy(mode: AppCompatibilityMode, wifi: Boolean, mobile: Boolean, explicit: Boolean, english: Boolean): String {
    return when (mode) {
        AppCompatibilityMode.CUSTOM -> if (english)
            "PERSONALIZED: the app stays inside HYDRA and uses only the protection switches selected for this app; Wi‑Fi/Mobile permissions remain separate."
        else
            "PERSONALIZADO: la app permanece dentro de HYDRA y usa solo las protecciones seleccionadas para esta app; los permisos Wi‑Fi/Móvil siguen siendo independientes."
        AppCompatibilityMode.EXCLUDED -> if (english)
            "NO FIREWALL: the app leaves HYDRA/VPN; HYDRA does not filter its traffic and Wi‑Fi/Mobile firewall switches do not apply."
        else
            "SIN FIREWALL: la app sale de HYDRA/VPN; HYDRA no filtra su tráfico y los controles Wi‑Fi/Móvil del firewall no aplican."
        AppCompatibilityMode.ESSENTIAL -> if (english)
            "PERMISSIVE: the app remains inside HYDRA; Wi‑Fi=${if (wifi) "ON" else "OFF"}, Mobile=${if (mobile) "ON" else "OFF"}; compatibility layers are relaxed and strong security remains active."
        else
            "PERMISIVO: la app permanece dentro de HYDRA; Wi‑Fi=${if (wifi) "ACTIVO" else "BLOQUEADO"}, Móvil=${if (mobile) "ACTIVO" else "BLOQUEADO"}; se relaja compatibilidad y se mantiene la seguridad fuerte."
        AppCompatibilityMode.NORMAL -> when {
            wifi && mobile -> if (english)
                "PERMITIR: Wi‑Fi and mobile are allowed through HYDRA; normal filtering and threat protection remain active."
            else
                "PERMITIR: Wi‑Fi y datos móviles pasan por HYDRA; el filtrado normal y la protección contra amenazas siguen activos."
            wifi -> if (english)
                "SOLO WI‑FI: Wi‑Fi is allowed through HYDRA; mobile data is blocked for this app."
            else
                "SOLO WI‑FI: Wi‑Fi pasa por HYDRA; los datos móviles quedan bloqueados para esta app."
            mobile -> if (english)
                "SOLO DATOS MÓVILES: mobile is allowed through HYDRA; Wi‑Fi is blocked for this app."
            else
                "SOLO DATOS MÓVILES: los datos móviles pasan por HYDRA; Wi‑Fi queda bloqueado para esta app."
            else -> if (english)
                "BLOQUEADA: Wi‑Fi and mobile are blocked; because there is no rule, the next network attempt will ask you."
            else
                "BLOQUEADA: Wi‑Fi y datos móviles están bloqueados; como no hay regla, el próximo intento de red preguntará."
        }
    }
}

internal fun appRulePolicyColor(
    compatibilityExcluded: Boolean,
    wifiAllowed: Boolean,
    mobileAllowed: Boolean
): Color {
    return when {
        compatibilityExcluded -> Color(0xFF123B66) // SIN FIREWALL
        wifiAllowed && mobileAllowed -> Color(0xFF2E7D32) // both networks
        wifiAllowed || mobileAllowed -> Color(0xFFB8860B) // exactly one network
        else -> Color(0xFFC62828) // neither network
    }
}

internal fun formatAnalyzerBytes(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / 1048576.0)
    bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "${bytes} B"
}

internal fun notifyRulesChanged(context: Context) {
    if (!FirewallVpnService.isRunning) return
    context.startService(Intent(context, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED })
}

internal fun loadNetworkApps(context: Context): List<AppEntry> {
    val pm = context.packageManager
    // getInstalledApplications is much lighter than getInstalledPackages(GET_PERMISSIONS) (hundreds of system apps with
    // long permission lists). INTERNET is a normal permission, so checkPermission tells whether the app can use the network.
    return runCatching {
        @Suppress("DEPRECATION")
        pm.getInstalledApplications(0).asSequence()
            .filter { it.packageName != context.packageName }
            .filter { info ->
                runCatching { pm.checkPermission(Manifest.permission.INTERNET, info.packageName) == PackageManager.PERMISSION_GRANTED }
                    .getOrDefault(true)
            }
            .map { info ->
                AppEntry(
                    label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(info.packageName),
                    packageName = info.packageName,
                    uid = info.uid,
                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                    processName = info.processName ?: info.packageName
                )
            }.distinctBy { "${it.packageName}:${it.uid}" }.sortedBy { it.label.lowercase() }.toList()
    }.getOrDefault(emptyList())
}

internal const val byteOrderMark = "\uFEFF"

internal fun buildHistoryCsv(records: List<ConnectionHistory.Record>): String {
    val sb = StringBuilder()
    sb.append("id,timestamp,hora,uid,aplicacion,protocolo,red,origen,destino,dominio,resultado,evento,repeticiones\n")
    records.forEach { r ->
        val host = extractHost(r.destination)
        val domain = DomainResolver.cached(host).orEmpty()
        val values = listOf(
            r.id.toString(), r.timestamp.toString(), r.time, r.uid.toString(), r.packageName.orEmpty(),
            r.protocol, r.network.displayName, r.source, r.destination, domain, if (r.allowed) "PERMITIDO" else "BLOQUEADO", r.event, r.repeatCount.toString()
        )
        sb.append(values.joinToString(",") { csvEscape(it) }).append('\n')
    }
    return sb.toString()
}

internal fun csvEscape(value: String): String = "\"${value.replace("\"", "\"\"")}\""

internal fun formatTrafficMb(mb: Float): String {
    val bytes = (mb.toDouble() * 1024.0 * 1024.0).coerceAtLeast(0.0)
    return when {
        bytes < 1024.0 -> String.format(java.util.Locale.US, "%.0f B", bytes)
        bytes < 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        bytes < 1024.0 * 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}

internal fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
    bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
}
