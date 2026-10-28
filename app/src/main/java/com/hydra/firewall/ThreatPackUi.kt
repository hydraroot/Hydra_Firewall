package com.hydra.firewall

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.hydra.firewall.security.ThreatPackStatusFormat
import com.hydra.firewall.security.ThreatSignatureStore
import com.hydra.firewall.security.ThreatSignatureUpdater
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Punto 6 — Estado del pack de amenazas y botón "Actualizar ahora".
 * Los textos y la clasificación (al día / vence pronto / vencido / solo el incluido) viven en
 * [ThreatPackStatusFormat] (pura y testeada).
 */
@Composable
fun ThreatPackCard(english: Boolean, refreshTrigger: Int, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var version by remember { mutableStateOf(0) }
    var updating by remember { mutableStateOf(false) }

    val status = remember(version, refreshTrigger) { ThreatSignatureStore.status(context) }
    val feedUrl = remember(version) { ThreatSignatureUpdater.configuredFeedUrl(context) }
    val feedConfigured = feedUrl.isNotBlank()
    val lastUpdate = remember(version, refreshTrigger) { ThreatSignatureStore.lastUpdate(context) }
    val summary = ThreatPackStatusFormat.summarize(status, feedConfigured, lastUpdate, System.currentTimeMillis())
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    fun date(ms: Long) = if (ms > 0) fmt.format(Date(ms)) else "—"
    fun t(es: String, en: String) = if (english) en else es

    val headlineColor = when (summary.health) {
        ThreatPackStatusFormat.Health.OK -> MaterialTheme.colorScheme.onSurface
        ThreatPackStatusFormat.Health.BUNDLED_ONLY -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.error
    }

    Column(modifier.fillMaxWidth().padding(vertical = 3.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(t("PACK DE AMENAZAS", "THREAT PACK"), style = MaterialTheme.typography.labelLarge)
        Text(summary.headline(english), style = MaterialTheme.typography.bodyMedium, color = headlineColor)
        Text("${t("Versión", "Version")}: ${status.packVersion}", style = MaterialTheme.typography.bodySmall)
        Text("${t("Generado", "Generated")}: ${date(status.generatedAt)}" + (summary.ageDays?.let { " (${t("hace $it d", "$it d ago")})" } ?: ""), style = MaterialTheme.typography.bodySmall)
        Text(
            "${t("Vence", "Expires")}: " + (if (status.expiresAt > 0) date(status.expiresAt) else t("no vence", "does not expire")),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            t(
                "Contiene: ${status.domainCount} dominios • ${status.ipCount} IPs • ${status.sha256Count} hashes • ${status.yaraRuleCount} reglas YARA",
                "Contains: ${status.domainCount} domains • ${status.ipCount} IPs • ${status.sha256Count} hashes • ${status.yaraRuleCount} YARA rules"
            ),
            style = MaterialTheme.typography.bodySmall
        )
        if (status.liveThreatDomainCount > 0) {
            Text(
                t("Dominios de amenaza en vivo: ${status.liveThreatDomainCount} (${status.liveThreatSource})", "Live threat domains: ${status.liveThreatDomainCount} (${status.liveThreatSource})"),
                style = MaterialTheme.typography.bodySmall
            )
        }
        if (status.sourceSummary.isNotEmpty()) {
            Text("${t("Fuentes", "Sources")}: ${status.sourceSummary.joinToString(" • ")}", style = MaterialTheme.typography.bodySmall, maxLines = 3)
        }
        Text(
            ThreatPackStatusFormat.updateModeText(feedConfigured, ThreatPackStatusFormat.hostOf(feedUrl), english),
            style = MaterialTheme.typography.bodySmall
        )
        Text("${t("Última actualización", "Last update")}: ${date(lastUpdate)}", style = MaterialTheme.typography.bodySmall)
        ThreatPackStatusFormat.friendlyError(status.lastUpdateError, english)?.let {
            Text("⚠ $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Button(
            enabled = feedConfigured && !updating,
            onClick = {
                updating = true
                ThreatSignatureUpdater.updateIfDue(context, force = true) { result ->
                    // El callback llega desde el hilo del actualizador: volvemos al principal.
                    Handler(Looper.getMainLooper()).post {
                        updating = false
                        version++
                        val msg = when {
                            result.success -> t("Pack actualizado: ${result.version ?: ""}", "Pack updated: ${result.version ?: ""}")
                            else -> ThreatPackStatusFormat.friendlyError(result.error, english) ?: t("Falló la actualización.", "Update failed.")
                        }
                        Toast.makeText(context.applicationContext, msg, Toast.LENGTH_LONG).show()
                    }
                }
            }
        ) {
            Text(
                when {
                    updating -> t("Actualizando…", "Updating…")
                    feedConfigured -> t("Actualizar ahora", "Update now")
                    else -> t("Actualizar (sin feed configurado)", "Update (no feed configured)")
                }
            )
        }
    }
}
