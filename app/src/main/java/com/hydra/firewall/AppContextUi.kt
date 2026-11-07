package com.hydra.firewall

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.ui.theme.HydraCard
import com.hydra.firewall.vpn.AppCompatibilityMode
import com.hydra.firewall.vpn.AppCompatibilityPolicyStore
import com.hydra.firewall.vpn.AppNames
import com.hydra.firewall.vpn.ConnectionHistory

/** A service another app commonly needs to work (Play Services for Drive backups, download manager, ...). */
data class AppDependency(val packageName: String, val label: String, val uid: Int, val whyEs: String, val whyEn: String)

/**
 * Optional "services this app uses". It is a curated list plus one automatic signal: apps that declare the Google Play
 * services version in their manifest also get Play Services and the Services Framework. Nothing is changed unless the
 * user flips a switch, and every switch is the normal per-app Wi‑Fi / mobile rule of that service.
 */
object AppDependencies {
    private const val GMS = "com.google.android.gms"
    private const val GSF = "com.google.android.gsf"
    private const val DRIVE = "com.google.android.apps.docs"
    private const val MEDIA = "com.google.android.providers.media.module"
    private const val DOWNLOADS = "com.android.providers.downloads"

    private val INFO: Map<String, Pair<String, String>> = mapOf(
        GMS to ("Inicio de sesión de Google, notificaciones push y copias de seguridad en Drive." to "Google sign-in, push notifications and Drive backups."),
        GSF to ("Registro del dispositivo y notificaciones de Google." to "Device registration and Google notifications."),
        "com.android.vending" to ("Licencias y actualizaciones de Google Play." to "Google Play licences and updates."),
        DRIVE to ("Google Drive: destino de la copia de seguridad." to "Google Drive: backup destination."),
        MEDIA to ("Almacenamiento multimedia: acceso a fotos y archivos." to "Media storage: access to photos and files."),
        "com.android.providers.media.module" to ("Almacenamiento multimedia: acceso a fotos y archivos." to "Media storage: access to photos and files."),
        DOWNLOADS to ("Administrador de descargas del sistema." to "System download manager.")
    )

    private val WHATSAPP = listOf(GMS, DRIVE, GSF, MEDIA, "com.android.providers.media.module", DOWNLOADS)

    private val CURATED: Map<String, List<String>> = mapOf(
        "com.whatsapp" to WHATSAPP,
        "com.whatsapp.w4b" to WHATSAPP,
        DRIVE to listOf(GMS, GSF, MEDIA, "com.android.providers.media.module"),
        "com.google.android.apps.photos" to listOf(GMS, GSF, MEDIA, "com.android.providers.media.module")
    )

    fun forApp(context: Context, packageName: String): List<AppDependency> {
        val pm = context.packageManager
        val ids = LinkedHashSet<String>()
        CURATED[packageName]?.let { ids.addAll(it) }
        val usesGms = runCatching {
            pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA).metaData?.containsKey("com.google.android.gms.version") == true
        }.getOrDefault(false)
        if (usesGms) { ids.add(GMS); ids.add(GSF) }
        ids.remove(packageName)
        val ownUid = runCatching { pm.getApplicationInfo(packageName, 0).uid }.getOrDefault(-1)
        val seenUids = HashSet<Int>()
        return ids.mapNotNull { pkg ->
            val info = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() ?: return@mapNotNull null
            if (info.uid == ownUid || !seenUids.add(info.uid)) return@mapNotNull null
            val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(pkg)
            val why = INFO[pkg]
            AppDependency(pkg, label, info.uid, why?.first.orEmpty(), why?.second.orEmpty())
        }
    }
}

/**
 * Expandable-row section for Rules. [effective] gives the Wi‑Fi / mobile state shown for a UID (same logic as the main
 * row) and [onSet] stores a new pair of values for that UID.
 */
@Composable
fun AppDependenciesSection(
    app: AppEntry,
    english: Boolean,
    ruleVersion: Int,
    effective: (Int) -> Pair<Boolean, Boolean>,
    onSet: (uid: Int, wifi: Boolean, mobile: Boolean) -> Unit
) {
    val context = LocalContext.current
    val deps = remember(app.packageName) { AppDependencies.forApp(context, app.packageName) }
    if (deps.isEmpty()) return
    Spacer(Modifier.height(10.dp))
    Text(
        if (english) "SERVICES THIS APP USES (OPTIONAL)" else "SERVICIOS QUE USA (OPCIONAL)",
        fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(
        if (english) "If this app fails even though it is allowed, it may depend on these. Each switch is the normal rule of that service."
        else "Si esta app falla aunque esté permitida, puede depender de estos servicios. Cada interruptor es la regla normal de ese servicio.",
        fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    deps.forEach { dep ->
        val excluded = AppCompatibilityPolicyStore.getMode(dep.packageName) == AppCompatibilityMode.EXCLUDED
        val (wifi, mobile) = remember(dep.uid, ruleVersion) { effective(dep.uid) }
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(end = 6.dp)) {
                Text(dep.label, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    if (excluded) (if (english) "No firewall · outside Hydra" else "Sin firewall · fuera de Hydra") else if (english) dep.whyEn else dep.whyEs,
                    fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Switch(checked = wifi, enabled = !excluded, onCheckedChange = { onSet(dep.uid, it, mobile) }, modifier = Modifier.height(24.dp).scale(0.72f))
                Text("Wi‑Fi", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.width(2.dp))
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Switch(checked = mobile, enabled = !excluded, onCheckedChange = { onSet(dep.uid, wifi, it) }, modifier = Modifier.height(24.dp).scale(0.72f))
                Text(if (english) "Data" else "Datos", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/** True when Hydra could not name the app behind a connection ("?", unknown UID or anonymous system process). */
fun isUnidentifiedApp(uid: Int, label: String): Boolean =
    uid < 0 || label == "?" ||
        label.startsWith("App desconocida") || label.startsWith("Unknown or uninstalled") ||
        label.startsWith("Proceso del sistema") || label.startsWith("System process")

data class OriginHints(val shared: List<String>, val installer: String?, val nearby: List<String>)

/**
 * Best-effort hints about who is behind an unidentified connection. Android does not tell a VPN which app started
 * another one, so these are clues only: other apps sharing the UID, who installed it, and which known apps were
 * active within five seconds.
 */
fun originHints(context: Context, record: ConnectionHistory.Record, history: List<ConnectionHistory.Record>): OriginHints {
    val pm = context.packageManager
    val shared = if (record.uid >= 0) runCatching {
        pm.getPackagesForUid(record.uid).orEmpty().map { pkg ->
            runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
        }.take(4)
    }.getOrDefault(emptyList()) else emptyList()
    val pkg = record.packageName?.takeIf { it.isNotBlank() } ?: runCatching { pm.getPackagesForUid(record.uid)?.firstOrNull() }.getOrNull()
    val installer = pkg?.let {
        runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(it).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(it)
        }.getOrNull()
    }?.takeIf { it.isNotBlank() }?.let { inst ->
        if (inst == "com.android.vending") "Google Play"
        else runCatching { pm.getApplicationLabel(pm.getApplicationInfo(inst, 0)).toString() }.getOrDefault(inst)
    }
    val nearby = history.asSequence()
        .filter { it.id != record.id && it.uid >= 0 && it.uid != record.uid && kotlin.math.abs(it.timestamp - record.timestamp) <= 5_000L }
        .map { AppNames.label(it.uid, it.packageName) }
        .filter { !isUnidentifiedApp(0, it) }
        .distinct().take(3).toList()
    return OriginHints(shared, installer, nearby)
}

@Composable
fun OriginHintBlock(record: ConnectionHistory.Record, history: List<ConnectionHistory.Record>, english: Boolean) {
    val context = LocalContext.current
    val label = AppNames.label(record.uid, record.packageName)
    if (!isUnidentifiedApp(record.uid, label)) return
    val hints = remember(record.id) { originHints(context, record, history) }
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(if (english) "Who started it?" else "¿Quién la inició?", style = MaterialTheme.typography.titleSmall)
            if (record.uid < 0) Text(
                if (english) "Android did not report which app owns this connection (usually a very short one)."
                else "Android no informó a qué app pertenece esta conexión (suele pasar con conexiones muy cortas).",
                style = MaterialTheme.typography.bodySmall
            )
            if (hints.shared.isNotEmpty()) Text(
                (if (english) "Packages with this UID: " else "Paquetes con este UID: ") + hints.shared.joinToString(", "),
                style = MaterialTheme.typography.bodySmall
            )
            hints.installer?.let {
                Text((if (english) "Installed by: " else "Instalada por: ") + it, style = MaterialTheme.typography.bodySmall)
            }
            if (hints.nearby.isNotEmpty()) Text(
                (if (english) "Apps active at that moment: " else "Apps activas en ese momento: ") + hints.nearby.joinToString(", "),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                if (english) "These are clues only: Android does not tell Hydra which app launched another."
                else "Son solo pistas: Android no le dice a Hydra qué app inició a otra.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * One entry per UID. Apps that share a UID are merged into a single representative (user apps first, then by name)
 * whose [AppEntry.members] lists every package, because Android attributes their traffic to the same UID and Hydra's
 * Wi‑Fi / mobile rule is stored per UID.
 */
fun groupAppsByUid(apps: List<AppEntry>): List<AppEntry> =
    apps.groupBy { it.uid }.map { (uid, list) ->
        if (list.size == 1) list[0] else {
            val sorted = list.sortedWith(compareBy<AppEntry>({ it.isSystem }, { it.label.lowercase() }))
            val rep = sorted.first()
            val label = if (uid == 1000) "Sistema Android · ${list.size}" else "${rep.label} +${list.size - 1}"
            rep.copy(label = label, isSystem = list.all { it.isSystem }, members = sorted)
        }
    }
