package com.hydra.firewall

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.ConfigPortability
import com.hydra.firewall.vpn.FirewallVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Pegamento con Android de [ConfigPortability] (la lógica pura y testeada vive allí).
 * Lee/escribe SharedPreferences y traduce UID <-> paquete con PackageManager.
 */
object ConfigTransfer {
    private const val BACKUP_FILE = "config-backup-before-import.json"

    fun snapshotPrefs(context: Context): Map<String, Map<String, Any?>> =
        ConfigPortability.EXPORTED_PREFS.associateWith { name ->
            context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE).all.mapValues { it.value }
        }

    private fun packagesForUid(context: Context, uid: Int): List<String> =
        runCatching { context.packageManager.getPackagesForUid(uid)?.toList() }.getOrNull().orEmpty()

    private fun uidForPackage(context: Context, pkg: String): Int? = try {
        context.packageManager.getApplicationInfo(pkg, 0).uid
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: Exception) {
        null
    }

    fun export(context: Context): ConfigPortability.ExportResult = ConfigPortability.export(
        snapshot = snapshotPrefs(context),
        packagesForUid = { packagesForUid(context, it) },
        meta = ConfigPortability.Meta(System.currentTimeMillis(), BuildConfig.VERSION_NAME, BuildConfig.APPLICATION_ID)
    )

    fun suggestedFileName(): String =
        "hydra-config-" + SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + ".json"

    /** Lee y valida el archivo; no escribe nada. */
    fun prepare(context: Context, text: String): Pair<ConfigPortability.ParsedConfig, ConfigPortability.ImportPlan> {
        val parsed = ConfigPortability.parse(text)
        val plan = ConfigPortability.plan(parsed, snapshotPrefs(context)) { uidForPackage(context, it) }
        return parsed to plan
    }

    fun hasBackup(context: Context): Boolean = File(context.filesDir, BACKUP_FILE).isFile

    /** Guarda una copia del estado actual (para "Deshacer") y aplica el plan. @return claves omitidas por tipo distinto. */
    fun apply(context: Context, plan: ConfigPortability.ImportPlan, saveBackup: Boolean = true): Int {
        val app = context.applicationContext
        if (saveBackup) {
            runCatching { File(app.filesDir, BACKUP_FILE).writeText(export(app).json, Charsets.UTF_8) }
        }
        val current = snapshotPrefs(app)
        var skipped = 0
        val prefNames = (plan.removeKeys.keys + plan.put.keys).toSet()
        for (name in prefNames) {
            val editor = app.getSharedPreferences(name, Context.MODE_PRIVATE).edit()
            plan.removeKeys[name].orEmpty().forEach { editor.remove(it) }
            for ((key, value) in plan.put[name].orEmpty()) {
                val existing = current[name]?.get(key)
                if (existing != null && !sameType(existing, value)) { skipped++; continue }
                when (value) {
                    is Boolean -> editor.putBoolean(key, value)
                    is Int -> editor.putInt(key, value)
                    is Long -> editor.putLong(key, value)
                    is Float -> editor.putFloat(key, value)
                    is String -> editor.putString(key, value)
                    is Set<*> -> editor.putStringSet(key, value.map { it.toString() }.toSet())
                    else -> skipped++
                }
            }
            editor.commit()
        }
        if (FirewallVpnService.isRunning) {
            runCatching {
                app.startService(Intent(app, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED })
            }
        }
        return skipped
    }

    fun restoreBackup(context: Context): ConfigPortability.ImportReport? {
        val f = File(context.filesDir, BACKUP_FILE)
        if (!f.isFile) return null
        val (_, plan) = prepare(context, f.readText(Charsets.UTF_8))
        apply(context, plan, saveBackup = false)
        return plan.report
    }

    private fun sameType(a: Any?, b: Any?): Boolean = when (a) {
        is Boolean -> b is Boolean
        is Int -> b is Int
        is Long -> b is Long
        is Float -> b is Float
        is String -> b is String
        is Set<*> -> b is Set<*>
        else -> false
    }

    fun readLimited(context: Context, uri: android.net.Uri): String {
        val limit = ConfigPortability.MAX_BYTES + 1
        val input = requireNotNull(context.contentResolver.openInputStream(uri)) { "No se pudo abrir el archivo" }
        return input.use { stream ->
            val buf = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(16 * 1024)
            while (buf.size() < limit) {
                val n = stream.read(chunk, 0, minOf(chunk.size, limit - buf.size()))
                if (n <= 0) break
                buf.write(chunk, 0, n)
            }
            buf.toString(Charsets.UTF_8.name())
        }
    }
}

@Composable
fun ConfigTransferCard(context: Context = LocalContext.current, english: Boolean, onImported: () -> Unit) {
    val scope = rememberCoroutineScope()
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var pending by remember { mutableStateOf<Pair<ConfigPortability.ParsedConfig, ConfigPortability.ImportPlan>?>(null) }
    var hasBackup by remember { mutableStateOf(ConfigTransfer.hasBackup(context)) }

    fun t(es: String, en: String) = if (english) en else es
    // El estado en pantalla se pierde cuando la pestaña se recompone tras importar; el Toast sí se ve.
    fun toast(msg: String) { android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_LONG).show() }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val json = pendingExport
        pendingExport = null
        if (uri == null || json == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray(Charsets.UTF_8)) } != null }.getOrDefault(false)
            }
            status = if (ok) t("Configuración exportada.", "Configuration exported.") else t("No se pudo guardar el archivo.", "Could not save the file.")
            toast(status.orEmpty())
        }
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { ConfigTransfer.prepare(context, ConfigTransfer.readLimited(context, uri)) }
            }
            result.onSuccess { pending = it; status = null }
                .onFailure {
                    status = if (it is ConfigPortability.ConfigFormatException) it.message
                    else t("No se pudo leer el archivo.", "Could not read the file.")
                }
        }
    }

    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            Text(t("Exportar / importar configuración", "Export / import configuration"), style = MaterialTheme.typography.titleSmall)
            Text(
                t(
                    "Guarda tus reglas, listas y ajustes en un archivo y los restaura en este u otro celular. Las reglas viajan por nombre de app, no por número interno, así que se aplican a la app correcta aunque cambie el celular. No incluye el PIN, el historial ni las estadísticas.",
                    "Saves your rules, lists and settings to a file and restores them on this or another phone. Rules travel by app name, not internal ID, so they apply to the right app on a different phone. The PIN, history and statistics are not included."
                ),
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { ConfigTransfer.export(context) }
                        pendingExport = r.json
                        status = t(
                            "Exportando ${r.stats.apps} apps, ${r.stats.advancedRules} reglas avanzadas…",
                            "Exporting ${r.stats.apps} apps, ${r.stats.advancedRules} advanced rules…"
                        )
                        exportLauncher.launch(ConfigTransfer.suggestedFileName())
                    }
                }) { Text(t("Exportar", "Export")) }
                OutlinedButton(onClick = { importLauncher.launch(arrayOf("application/json", "text/plain", "application/octet-stream", "*/*")) }) {
                    Text(t("Importar", "Import"))
                }
                if (hasBackup) {
                    TextButton(onClick = {
                        scope.launch {
                            val rep = withContext(Dispatchers.IO) { runCatching { ConfigTransfer.restoreBackup(context) }.getOrNull() }
                            status = if (rep != null) t("Se restauró la copia anterior a la última importación.", "Restored the copy made before the last import.")
                            else t("No se pudo restaurar la copia.", "Could not restore the copy.")
                            toast(status.orEmpty())
                            if (rep != null) onImported()
                        }
                    }) { Text(t("Deshacer", "Undo")) }
                }
            }
            status?.let {
                Spacer(Modifier.height(6.dp))
                Text(it, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    pending?.let { (parsed, plan) ->
        val r = plan.report
        AlertDialog(
            onDismissRequest = { pending = null },
            title = { Text(t("Importar configuración", "Import configuration")) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (parsed.createdAt > 0L) {
                        Text(t("Archivo del ", "File from ") + SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(parsed.createdAt)) +
                            (if (parsed.appVersion.isNotBlank()) " • v${parsed.appVersion}" else ""), style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(6.dp))
                    }
                    Text(t("Se aplicarán:", "Will be applied:"), style = MaterialTheme.typography.titleSmall)
                    Text(t("• Reglas de ${r.appsApplied} apps", "• Rules for ${r.appsApplied} apps"))
                    Text(t("• ${r.advancedApplied} reglas avanzadas", "• ${r.advancedApplied} advanced rules"))
                    Text(t("• ${r.ipApplied} excepciones de IP por app", "• ${r.ipApplied} per-app IP exceptions"))
                    if (parsed.essentialApps != null) Text(t("• ${r.essentialApplied} apps permisivas", "• ${r.essentialApplied} permissive apps"))
                    Text(t("• ${r.globalKeys} ajustes y listas globales", "• ${r.globalKeys} global settings and lists"))
                    if (r.appsMissing.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(t("No instaladas aquí (se omiten): ${r.appsMissing.size}", "Not installed here (skipped): ${r.appsMissing.size}"), style = MaterialTheme.typography.titleSmall)
                        r.appsMissing.take(8).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                        if (r.appsMissing.size > 8) Text("… +${r.appsMissing.size - 8}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (r.advancedSkipped + r.ipSkipped > 0) {
                        Spacer(Modifier.height(6.dp))
                        Text(t("Omitidas por apps ausentes o inválidas: ${r.advancedSkipped} reglas avanzadas, ${r.ipSkipped} IP",
                            "Skipped (missing/invalid apps): ${r.advancedSkipped} advanced rules, ${r.ipSkipped} IP"), style = MaterialTheme.typography.bodySmall)
                    }
                    if (r.ignoredKeys.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(t("Ajustes ignorados por seguridad: ${r.ignoredKeys.size}", "Settings ignored for safety: ${r.ignoredKeys.size}"), style = MaterialTheme.typography.bodySmall)
                    }
                    Spacer(Modifier.height(10.dp))
                    Text(
                        t(
                            "Esto REEMPLAZA tus reglas por app, reglas avanzadas y excepciones de IP actuales. Se guarda una copia automática para poder deshacer. Importá solo archivos de tu confianza: un archivo ajeno puede permitir apps que hoy están bloqueadas.",
                            "This REPLACES your current per-app rules, advanced rules and IP exceptions. An automatic copy is saved so you can undo. Only import files you trust: a foreign file could allow apps that are currently blocked."
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val plan0 = plan
                    pending = null
                    scope.launch {
                        val skipped = withContext(Dispatchers.IO) { runCatching { ConfigTransfer.apply(context, plan0) }.getOrNull() }
                        hasBackup = ConfigTransfer.hasBackup(context)
                        status = if (skipped == null) t("Falló la importación.", "Import failed.")
                        else t("Configuración importada. Para asegurar que todo se aplique, cerrá y abrí la app.", "Configuration imported. To make sure everything applies, close and reopen the app.") +
                            (if (skipped > 0) t(" ($skipped ajustes omitidos por tipo distinto)", " ($skipped settings skipped: different type)") else "")
                        toast(status.orEmpty())
                        if (skipped != null) onImported()
                    }
                }) { Text(t("Importar", "Import")) }
            },
            dismissButton = { TextButton(onClick = { pending = null }) { Text(t("Cancelar", "Cancel")) } }
        )
    }
}
