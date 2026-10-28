package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.AppDailyUsageStore
import com.hydra.firewall.vpn.AppUsageInsights
import com.hydra.firewall.vpn.TrafficStatsStore
import kotlinx.coroutines.delay

/**
 * Punto 5 — Consumo por app: ranking con banderas para detectar apps que "hablan de más".
 * Rangos: sesión actual (con subida/bajada y conexiones), hoy y últimos 7 días (solo bytes totales,
 * guardados localmente por [AppDailyUsageStore]). La lógica está en [AppUsageInsights] (testeada).
 */
@Composable
fun AppUsageCard(english: Boolean, sessionStats: List<TrafficStatsStore.Snapshot>, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var range by remember { mutableStateOf(0) } // 0 = sesión, 1 = hoy, 2 = 7 días
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) { delay(5_000L); tick++ }
    }

    val rows = remember(range, tick, sessionStats) {
        val inputs = when (range) {
            0 -> sessionStats.map {
                AppUsageInsights.Input(it.packageName ?: "uid:${it.uid}", it.packageName, it.uid, it.txBytes, it.rxBytes, it.connections, it.blocked)
            }
            else -> (if (range == 1) AppDailyUsageStore.todayTotals() else AppDailyUsageStore.lastDaysTotals(7)).map { (key, bytes) ->
                // El libro diario solo guarda el total por app (sin subida/bajada ni conexiones).
                AppUsageInsights.Input(key, key.takeUnless { it.startsWith("uid:") }, key.removePrefix("uid:").toIntOrNull() ?: -1, 0L, bytes, 0L, 0L)
            }
        }
        AppUsageInsights.rank(inputs, topN = 10)
    }
    val labels = remember(rows) { rows.associate { it.key to appLabel(context, it.packageName, it.uid) } }

    Column(modifier.fillMaxWidth().padding(vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(if (english) "Usage by app" else "Consumo por app", style = MaterialTheme.typography.titleSmall)
        Text(
            if (english) "Spot apps that talk too much. Flags are hints, not proof that something is wrong."
            else "Para detectar apps que hablan de más. Las banderas son pistas, no prueba de que algo ande mal.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(
                0 to (if (english) "Session" else "Sesión"),
                1 to (if (english) "Today" else "Hoy"),
                2 to (if (english) "7 days" else "7 días")
            ).forEach { (id, text) ->
                if (range == id) Button(onClick = { range = id }) { Text(text) }
                else OutlinedButton(onClick = { range = id }) { Text(text) }
            }
        }
        if (rows.isEmpty()) {
            Text(
                if (english) "No traffic recorded in this range yet." else "Todavía no hay tráfico registrado en este rango.",
                style = MaterialTheme.typography.bodySmall
            )
        }
        rows.forEach { r ->
            Column(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(labels[r.key] ?: r.key, style = MaterialTheme.typography.bodyMedium, maxLines = 1, modifier = Modifier.weight(1f))
                    Text("${AppUsageInsights.formatBytes(r.totalBytes)} · ${r.sharePercent}%", style = MaterialTheme.typography.labelMedium)
                }
                LinearProgressIndicator(progress = { (r.sharePercent / 100f).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth().height(4.dp))
                if (range == 0) {
                    Text(
                        (if (english) "↑ " else "↑ ") + AppUsageInsights.formatBytes(r.txBytes) + "  ↓ " + AppUsageInsights.formatBytes(r.rxBytes) +
                            (if (english) "  · ${r.connections} connections · ${r.blocked} blocked" else "  · ${r.connections} conexiones · ${r.blocked} bloqueos"),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (r.flags.isNotEmpty()) {
                    Text(
                        "⚠ " + r.flags.joinToString(" • ") { AppUsageInsights.flagText(it, english) },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
        Spacer(Modifier.height(2.dp))
    }
}

private fun appLabel(context: Context, packageName: String?, uid: Int): String {
    if (packageName.isNullOrBlank()) return if (uid >= 0) "UID $uid" else "?"
    return runCatching {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString().takeIf { it.isNotBlank() }
    }.getOrNull() ?: packageName
}
