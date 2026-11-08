package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.security.ThreatSignatureStore
import com.hydra.firewall.ui.theme.HydraCard
import com.hydra.firewall.vpn.AlertEngine
import com.hydra.firewall.vpn.AlertStore
import com.hydra.firewall.vpn.AppNames
import com.hydra.firewall.vpn.ConnectionHistory
import com.hydra.firewall.vpn.DnsIpCorrelationStore
import com.hydra.firewall.vpn.DomainBlockStore
import com.hydra.firewall.vpn.FirewallVpnService
import com.hydra.firewall.vpn.RuleStore
import com.hydra.firewall.vpn.TempAllowManager
import java.net.InetAddress

private val HealthOk = Color(0xFF34D399)
private val HealthWarn = Color(0xFFFBBF24)
private val HealthBad = Color(0xFFF87171)

/** Puntaje simple 0..100: firewall apagado pesa mucho; cada aviso pendiente resta. */
internal fun healthScore(isOn: Boolean, pendingAlerts: Int): Int {
    if (!isOn) return 25
    return (100 - pendingAlerts.coerceAtMost(3) * 12).coerceIn(0, 100)
}

/**
 * Tarjeta de estado de Inicio: anillo con el puntaje, un título claro, chips con los números y el botón
 * «Una app no funciona».
 */
@Composable
fun HomeHealthCard(
    context: Context,
    english: Boolean,
    isOn: Boolean,
    blockedToday: Long,
    onOpenAssistant: () -> Unit
) {
    val pending = AlertStore.pendingCount(context)
    val score = healthScore(isOn, pending)
    val color = when {
        score >= 80 -> HealthOk
        score >= 50 -> HealthWarn
        else -> HealthBad
    }
    val title = when {
        !isOn -> if (english) "Firewall stopped" else "Firewall detenido"
        pending > 0 -> if (english) "Needs your attention" else "Necesita tu atención"
        else -> if (english) "Everything is in order" else "Todo en orden"
    }
    val sub = when {
        !isOn -> if (english) "No traffic is being filtered." else "No se está filtrando el tráfico."
        pending > 0 -> if (english) "$pending alert(s) waiting for your decision." else "$pending aviso(s) esperando tu decisión."
        else -> if (english) "Nothing needs your decision right now." else "Nada necesita tu decisión por ahora."
    }
    val track = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(64.dp), contentAlignment = Alignment.Center) {
                    Canvas(Modifier.size(64.dp)) {
                        val stroke = 8.dp.toPx()
                        val inset = stroke / 2f
                        val arcSize = Size(size.width - stroke, size.height - stroke)
                        drawArc(track, 0f, 360f, false, Offset(inset, inset), arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
                        drawArc(color, -90f, 360f * score / 100f, false, Offset(inset, inset), arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
                    }
                    Text(score.toString(), fontWeight = FontWeight.Bold, fontSize = 18.sp)
                }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(title, fontWeight = FontWeight.Bold, fontSize = 16.sp, color = color)
                    Text(sub, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                HealthChip(if (isOn) (if (english) "Active" else "Activo") else (if (english) "Off" else "Apagado"), if (isOn) HealthOk else HealthBad)
                HealthChip((if (english) "Blocked today " else "Bloqueos hoy ") + blockedToday, MaterialTheme.colorScheme.onSurfaceVariant)
                if (pending > 0) HealthChip((if (english) "Alerts " else "Avisos ") + pending, HealthWarn)
            }
            Spacer(Modifier.height(10.dp))
            Text(
                if (english) "An app isn't working" else "Una app no funciona",
                color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp,
                modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.primary)
                    .clickable { onOpenAssistant() }.padding(vertical = 11.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

@Composable
private fun HealthChip(text: String, color: Color) {
    Text(
        text, color = color, fontSize = 10.5.sp, fontWeight = FontWeight.SemiBold, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(50)).background(color.copy(alpha = 0.14f)).padding(horizontal = 9.dp, vertical = 4.dp)
    )
}

private enum class BlockKind { SERVICE, TRACKER, UNKNOWN }

private data class BlockedGroup(val uid: Int, val packageName: String?, val label: String, val hosts: List<String>, val count: Int, val kind: BlockKind)

private val serviceSuffixes = listOf(
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "googleusercontent.com", "whatsapp.net", "whatsapp.com",
    "facebook.com", "fbcdn.net", "microsoft.com", "windowsupdate.com", "apple.com", "icloud.com", "amazonaws.com", "cloudfront.net"
)

private fun classify(context: Context, host: String): BlockKind {
    if (DomainBlockStore.matchesWithoutCounting(host) || ThreatSignatureStore.matchDomain(context, host) != null) return BlockKind.TRACKER
    val base = host.lowercase()
    if (serviceSuffixes.any { base == it || base.endsWith(".$it") }) return BlockKind.SERVICE
    return BlockKind.UNKNOWN
}

private fun collectBlocked(context: Context, since: Long): List<BlockedGroup> {
    val blocked = ConnectionHistory.snapshot().filter { !it.allowed && it.timestamp >= since }
    return blocked.groupBy { it.uid }.map { (uid, recs) ->
        val hosts = recs.map { r ->
            val ip = AlertEngine.parseHost(r.destination)
            val dom = ip?.let { runCatching { DnsIpCorrelationStore.lookup(r.uid, InetAddress.getByName(it)) }.getOrNull() }
            dom ?: ip ?: r.destination
        }.distinct()
        val kinds = hosts.map { classify(context, it) }
        // Si todo lo bloqueado es rastreador/publicidad, el grupo es "rastreador"; si hay algo de servicio, gana "servicio".
        val kind = when {
            kinds.any { it == BlockKind.SERVICE } -> BlockKind.SERVICE
            kinds.isNotEmpty() && kinds.all { it == BlockKind.TRACKER } -> BlockKind.TRACKER
            else -> BlockKind.UNKNOWN
        }
        BlockedGroup(uid, recs.first().packageName, AppNames.label(uid, recs.first().packageName), hosts, recs.sumOf { it.repeatCount }, kind)
    }.sortedWith(compareBy<BlockedGroup> { it.kind == BlockKind.TRACKER }.thenByDescending { it.count })
}

/**
 * Asistente «Una app no funciona»: se abre, el usuario prueba la app, y al volver Hydra muestra qué se bloqueó
 * en ese lapso, clasificado como servicio / rastreador / desconocido, con Permitir / Permitir 1 h / Ignorar.
 */
@Composable
fun AppNotWorkingAssistant(context: Context, english: Boolean, onDismiss: () -> Unit) {
    var step by remember { mutableStateOf(0) }
    var startedAt by remember { mutableStateOf(0L) }
    var groups by remember { mutableStateOf(emptyList<BlockedGroup>()) }
    var done by remember { mutableStateOf(setOf<Int>()) }
    val ruleStore = remember { RuleStore(context.applicationContext) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (english) "An app isn't working" else "Una app no funciona") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                when (step) {
                    0 -> Text(
                        if (english) "Hydra will watch what it blocks while you try the app, then tell you what is likely getting in the way."
                        else "Hydra va a mirar qué bloquea mientras probás la app y después te dice qué es lo que probablemente la traba."
                    )
                    1 -> Text(
                        if (english) "Recording. Open the app now and try what fails (a backup, a login, a download). Come back here and tap Done."
                        else "Grabando. Abrí la app ahora y probá lo que falla (un backup, un login, una descarga). Volvé acá y tocá Listo."
                    )
                    else -> {
                        if (groups.isEmpty()) {
                            Text(
                                if (english) "Hydra blocked nothing in that time, so the firewall is probably not the cause. Check that the app isn't paused, that it has permission, and that it works with the firewall off."
                                else "Hydra no bloqueó nada en ese lapso, así que probablemente el firewall no es la causa. Revisá que la app no esté pausada, que tenga permisos y probá si funciona con el firewall apagado."
                            )
                        }
                        groups.forEach { g ->
                            val kindLabel = when (g.kind) {
                                BlockKind.SERVICE -> if (english) "Service" else "Servicio"
                                BlockKind.TRACKER -> if (english) "Tracker" else "Rastreador"
                                BlockKind.UNKNOWN -> if (english) "Unknown" else "Desconocido"
                            }
                            val kindColor = when (g.kind) {
                                BlockKind.SERVICE -> HealthOk
                                BlockKind.TRACKER -> HealthBad
                                BlockKind.UNKNOWN -> HealthWarn
                            }
                            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(g.label, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    HealthChip(kindLabel, kindColor)
                                }
                                Text(
                                    (if (english) "${g.count} blocked · " else "${g.count} bloqueos · ") + g.hosts.take(3).joinToString(", "),
                                    fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 2, overflow = TextOverflow.Ellipsis,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                if (g.kind == BlockKind.TRACKER) Text(
                                    if (english) "Probably not what you need: ads/tracking. Leave it blocked." else "Probablemente no es lo que necesitás: publicidad o rastreo. Dejalo bloqueado.",
                                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(Modifier.height(6.dp))
                                if (g.uid in done) {
                                    Text(if (english) "Done. Try the app again." else "Listo. Probá la app de nuevo.", color = HealthOk, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                                } else {
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                        TextButton(onClick = {
                                            ruleStore.setWifiAllowed(g.uid, true)
                                            ruleStore.setMobileAllowed(g.uid, true)
                                            notifyRules(context)
                                            done = done + g.uid
                                        }) { Text(if (english) "Allow app" else "Permitir app", fontSize = 12.sp) }
                                        TextButton(onClick = {
                                            TempAllowManager.allow(context, g.uid, 60)
                                            done = done + g.uid
                                        }) { Text(if (english) "Allow 1 h" else "Permitir 1 h", fontSize = 12.sp) }
                                        TextButton(onClick = { groups = groups.filter { it.uid != g.uid } }) {
                                            Text(if (english) "Ignore" else "Ignorar", fontSize = 12.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            when (step) {
                0 -> TextButton(onClick = { startedAt = System.currentTimeMillis(); step = 1 }) { Text(if (english) "Start" else "Empezar") }
                1 -> TextButton(onClick = { groups = collectBlocked(context, startedAt); step = 2 }) { Text(if (english) "Done" else "Listo") }
                else -> TextButton(onClick = onDismiss) { Text(if (english) "Close" else "Cerrar") }
            }
        },
        dismissButton = {
            if (step < 2) TextButton(onClick = onDismiss) { Text(if (english) "Cancel" else "Cancelar") }
        }
    )
}

private fun notifyRules(context: Context) {
    if (!FirewallVpnService.isRunning) return
    context.startService(
        android.content.Intent(context, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED }
    )
}
