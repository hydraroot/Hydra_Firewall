package com.hydra.firewall

import android.content.Context
import com.hydra.firewall.ui.theme.HydraCard
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.vpn.PauseManager
import com.hydra.firewall.vpn.WeeklyStats

/**
 * Pause control for Home. While the firewall is ON it offers "Pause 15 min / 1 h"; while paused it shows a
 * countdown and "Resume now". [onResume] goes through the normal start path (it asks for the VPN permission if needed).
 */
@Composable
fun PauseCard(context: Context, english: Boolean, isOn: Boolean, onResume: () -> Unit) {
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            now = System.currentTimeMillis()
            kotlinx.coroutines.delay(1000)
        }
    }
    @Suppress("UNUSED_VARIABLE") val tick = now
    val remaining = PauseManager.remainingMs(context)
    fun t(es: String, en: String) = if (english) en else es

    if (isOn) {
        // A pause that is still stored while the firewall is already on (started by hand): forget it.
        if (remaining > 0L) PauseManager.clear(context)
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(t("¿Una app no anda?", "An app is not working?"), fontWeight = FontWeight.Bold)
                Text(
                    t("Pausá Hydra un rato para probar. Se reactiva sola.", "Pause Hydra for a while to test. It turns back on by itself."),
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = { PauseManager.pause(context, 15) }) {
                        Text(t("Pausar 15 min", "Pause 15 min"), maxLines = 1)
                    }
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = { PauseManager.pause(context, 60) }) {
                        Text(t("Pausar 1 hora", "Pause 1 hour"), maxLines = 1)
                    }
                }
            }
        }
    } else if (remaining > 0L) {
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    t("⏸ En pausa: vuelve en ", "⏸ Paused: back in ") + PauseManager.formatRemaining(remaining),
                    fontWeight = FontWeight.Bold
                )
                Text(
                    t("Durante la pausa no hay protección. Hydra se reactiva sola al terminar.", "There is no protection during the pause. Hydra turns back on when it ends."),
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(modifier = Modifier.fillMaxWidth(), onClick = onResume) { Text(t("Reanudar ahora", "Resume now")) }
            }
        }
    }
}

/** Last 7 days at a glance, from the small counters in [WeeklyStats]. Hidden until there is something to show. */
@Composable
fun WeeklySummaryCard(context: Context, english: Boolean) {
    val summary = remember { WeeklyStats.summary() }
    if (summary.isEmpty) return
    fun t(es: String, en: String) = if (english) en else es
    fun n(v: Long) = String.format(java.util.Locale.getDefault(), "%,d", v)
    val pm = context.packageManager
    val names = summary.top.map { (pkg, count) ->
        val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
        "$label (${n(count)})"
    }
    HydraCard(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(t("📊 Últimos 7 días", "📊 Last 7 days"), fontWeight = FontWeight.Bold)
            Text(t("🛡 ${n(summary.blocked)} intentos bloqueados", "🛡 ${n(summary.blocked)} blocked attempts"), fontSize = 13.sp)
            Text(t("🚫 ${n(summary.ads)} anuncios y rastreadores bloqueados", "🚫 ${n(summary.ads)} ads and trackers blocked"), fontSize = 13.sp)
            Text(t("✅ ${n(summary.allowed)} conexiones permitidas", "✅ ${n(summary.allowed)} allowed connections"), fontSize = 13.sp)
            if (names.isNotEmpty()) {
                Text(
                    t("Apps con más bloqueos: ", "Apps with most blocks: ") + names.joinToString(", "),
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
