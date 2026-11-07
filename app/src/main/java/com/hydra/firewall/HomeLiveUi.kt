package com.hydra.firewall

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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.ui.theme.HydraCard
import com.hydra.firewall.vpn.AppNames
import com.hydra.firewall.vpn.ConnectionHistory
import com.hydra.firewall.vpn.NetworkKind

private val LiveOk = Color(0xFF34D399)
private val LiveBad = Color(0xFFF87171)

/** Compact status row: dot + title + network + the firewall switch. Replaces the big "Firewall VPN" card on Home. */
@Composable
fun HomeStatusRow(
    english: Boolean,
    isOn: Boolean,
    network: NetworkKind,
    roaming: Boolean,
    onToggleVpn: (Boolean) -> Unit
) {
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(9.dp).clip(CircleShape).background(if (isOn) LiveOk else LiveBad))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    if (isOn) (if (english) "Firewall active" else "Firewall activo") else (if (english) "Firewall stopped" else "Firewall detenido"),
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    if (isOn) "${network.displayName}${if (roaming) " • Roaming" else ""}" else (if (english) "No traffic is being filtered" else "No se está filtrando el tráfico"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = isOn, onCheckedChange = onToggleVpn)
        }
    }
}

/**
 * Live traffic card. [history] holds (allowedMb, blockedMb) per refresh interval, newest last (same list the Stats tab uses).
 * Big number = data moved in the latest interval; right side = connections blocked today.
 */
@Composable
fun HomeLiveTrafficCard(
    english: Boolean,
    history: List<Pair<Float, Float>>,
    blockedToday: Long
) {
    val primary = MaterialTheme.colorScheme.primary
    val grid = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
    val last = history.lastOrNull() ?: (0f to 0f)
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Bottom) {
                Column {
                    Text(if (english) "NOW" else "AHORA", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(formatMb(last.first + last.second), fontSize = 26.sp, fontWeight = FontWeight.Bold)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(if (english) "BLOCKED TODAY" else "BLOQUEOS HOY", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(blockedToday.toString(), fontSize = 20.sp, fontWeight = FontWeight.Medium, color = LiveBad)
                }
            }
            Spacer(Modifier.height(10.dp))
            Canvas(Modifier.fillMaxWidth().height(72.dp)) {
                val maxVal = maxOf(history.maxOfOrNull { it.first } ?: 0f, history.maxOfOrNull { it.second } ?: 0f, 0.01f) * 1.1f
                for (f in listOf(0f, 0.5f, 1f)) {
                    val y = size.height - f * size.height
                    drawLine(grid, androidx.compose.ui.geometry.Offset(0f, y), androidx.compose.ui.geometry.Offset(size.width, y), strokeWidth = 1f)
                }
                if (history.size >= 2) {
                    val stepX = size.width / (history.size - 1)
                    fun y(v: Float) = size.height - (v / maxVal) * size.height
                    fun line(pick: (Pair<Float, Float>) -> Float) = Path().apply {
                        history.forEachIndexed { i, v -> if (i == 0) moveTo(0f, y(pick(v))) else lineTo(i * stepX, y(pick(v))) }
                    }
                    fun drawSeries(pick: (Pair<Float, Float>) -> Float, color: Color) {
                        val l = line(pick)
                        val fill = Path().apply { addPath(l); lineTo(size.width, size.height); lineTo(0f, size.height); close() }
                        drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = 0.28f), color.copy(alpha = 0f))))
                        drawPath(l, color, style = Stroke(width = 4f, cap = StrokeCap.Round, join = StrokeJoin.Round))
                        drawCircle(color, radius = 6f, center = androidx.compose.ui.geometry.Offset(size.width, y(pick(history.last()))))
                    }
                    drawSeries({ it.first }, primary)
                    drawSeries({ it.second }, LiveBad)
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).clip(CircleShape).background(primary))
                Spacer(Modifier.width(4.dp)); Text(if (english) "Allowed" else "Permitido", style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.width(12.dp))
                Box(Modifier.size(8.dp).clip(CircleShape).background(LiveBad))
                Spacer(Modifier.width(4.dp)); Text(if (english) "Blocked" else "Bloqueado", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

/** Last connection decisions (allowed/blocked) with app name and destination. Tapping the header opens the Connections tab. */
@Composable
fun HomeRecentDecisionsCard(
    english: Boolean,
    history: List<ConnectionHistory.Record>,
    limit: Int = 6,
    onOpenConnections: () -> Unit
) {
    val rows = remember(history) { history.take(limit) }
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp)) {
            Row(Modifier.fillMaxWidth().clickable { onOpenConnections() }.padding(bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(if (english) "LATEST DECISIONS" else "ÚLTIMAS DECISIONES", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
                Text(if (english) "See all" else "Ver todo", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
            }
            if (rows.isEmpty()) {
                Text(
                    if (english) "No connections yet. Activity will show up here." else "Todavía no hay conexiones. La actividad va a aparecer acá.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
            rows.forEachIndexed { i, r ->
                val color = if (r.allowed) LiveOk else LiveBad
                Row(Modifier.fillMaxWidth().padding(vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
                    val name = AppNames.label(r.uid, r.packageName)
                    Box(Modifier.size(28.dp).clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
                        Text(name.take(1).uppercase(), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                    Spacer(Modifier.width(9.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            "${r.protocol} • ${r.destination}",
                            fontSize = 10.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        (if (r.allowed) (if (english) "ALLOWED" else "PERMITIDO") else (if (english) "BLOCKED" else "BLOQUEADO")) +
                            if (!r.allowed && r.repeatCount > 1) " ×${r.repeatCount}" else "",
                        color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold,
                        modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(color.copy(alpha = 0.16f)).padding(horizontal = 6.dp, vertical = 3.dp)
                    )
                }
                if (i < rows.lastIndex) Box(Modifier.fillMaxWidth().height(1.dp).background(MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)))
            }
        }
    }
}

private fun formatMb(mb: Float): String {
    val bytes = (mb.toDouble() * 1024.0 * 1024.0).coerceAtLeast(0.0)
    return when {
        bytes < 1024.0 -> String.format(java.util.Locale.US, "%.0f B", bytes)
        bytes < 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        bytes < 1024.0 * 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
