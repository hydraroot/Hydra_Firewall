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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.ui.theme.HydraCard
import com.hydra.firewall.vpn.DailyTrafficStore
import java.text.SimpleDateFormat
import java.util.Locale

private val ScreenOk = Color(0xFF34D399)
private val ScreenBad = Color(0xFFF87171)
private val ScreenWarn = Color(0xFFFBBF24)

/** Segmented control used for the sub-tabs of each section and for filters (3.0.0 look). */
@Composable
fun HydraSegmented(
    options: List<String>,
    selected: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.78f))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        options.forEachIndexed { i, label ->
            val on = i == selected
            Box(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .background(if (on) MaterialTheme.colorScheme.primaryContainer else Color.Transparent)
                    .clickable { onSelect(i) }
                    .padding(vertical = 8.dp, horizontal = 2.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    label,
                    fontSize = 11.sp,
                    fontWeight = if (on) FontWeight.SemiBold else FontWeight.Medium,
                    color = if (on) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

/** Small ALLOWED / BLOCKED badge, with a repeat counter for blocked groups ("BLOQUEADO ×14"). */
@Composable
fun ConnStatusBadge(allowed: Boolean, english: Boolean, repeat: Int = 1) {
    val color = if (allowed) ScreenOk else ScreenBad
    val text = (if (allowed) (if (english) "ALLOWED" else "PERMITIDO") else (if (english) "BLOCKED" else "BLOQUEADO")) +
        if (!allowed && repeat > 1) " ×$repeat" else ""
    Text(
        text,
        color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(50)).background(color.copy(alpha = 0.14f)).padding(horizontal = 9.dp, vertical = 5.dp)
    )
}

/** Round app initial used where the real icon is not at hand. */
@Composable
fun AppInitial(name: String, modifier: Modifier = Modifier) {
    Box(
        modifier.size(34.dp).clip(RoundedCornerShape(11.dp)).background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center
    ) { Text(name.take(1).uppercase(), fontWeight = FontWeight.Bold, fontSize = 14.sp) }
}

@Composable
fun StatTile(modifier: Modifier, value: String, label: String, valueColor: Color = Color.Unspecified) {
    HydraCard(modifier, shape = RoundedCornerShape(19.dp)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 13.dp, vertical = 12.dp)) {
            Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = valueColor, maxLines = 1)
            Text(label, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
        }
    }
}

private fun fmtBytes(bytes: Long): String = when {
    bytes < 1024L -> "$bytes B"
    bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
}

/**
 * Stats header: range selector (today / 7 days) and three figures.
 * [days] is [DailyTrafficStore.lastDays] (newest first). Today vs yesterday is shown as a percentage of blocked bytes.
 */
@Composable
fun StatsSummary(english: Boolean, range: Int, onRange: (Int) -> Unit, days: List<DailyTrafficStore.Day>) {
    val shown = if (range == 0) days.take(1) else days
    val allowed = shown.sumOf { it.allowed }
    val blocked = shown.sumOf { it.blocked }
    val today = days.getOrNull(0)?.blocked ?: 0L
    val yesterday = days.getOrNull(1)?.blocked ?: 0L
    val delta = if (yesterday > 0L) ((today - yesterday) * 100L / yesterday) else null
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        HydraSegmented(
            listOf(if (english) "Today" else "Hoy", if (english) "7 days" else "7 días"),
            range, onRange
        )
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile(Modifier.weight(1f), fmtBytes(allowed), if (english) "allowed" else "permitido")
            StatTile(Modifier.weight(1f), fmtBytes(blocked), if (english) "blocked" else "bloqueado", ScreenBad)
            StatTile(
                Modifier.weight(1f),
                if (delta == null) "—" else (if (delta > 0) "+$delta%" else "$delta%"),
                if (english) "blocked vs yesterday" else "bloqueado vs ayer"
            )
        }
    }
}

/** Last 7 days as stacked bars (allowed + blocked bytes). [days] newest first; drawn oldest to newest. */
@Composable
fun WeekStackedBarsCard(english: Boolean, days: List<DailyTrafficStore.Day>) {
    val ordered = remember(days) { days.reversed() }
    val allowedColor = MaterialTheme.colorScheme.primary
    val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
    val maxTotal = (ordered.maxOfOrNull { it.allowed + it.blocked } ?: 0L).coerceAtLeast(1L)
    val letters = remember(ordered) {
        ordered.map { d ->
            runCatching {
                val parsed = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(d.key)
                SimpleDateFormat("EEE", Locale.getDefault()).format(parsed!!).take(1).uppercase()
            }.getOrDefault("")
        }
    }
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(if (english) "PER DAY" else "POR DÍA", fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(allowedColor))
                    Spacer(Modifier.width(4.dp)); Text(if (english) "Allowed" else "Permitido", fontSize = 10.sp)
                    Spacer(Modifier.width(10.dp))
                    Box(Modifier.size(8.dp).clip(CircleShape).background(ScreenBad))
                    Spacer(Modifier.width(4.dp)); Text(if (english) "Blocked" else "Bloqueado", fontSize = 10.sp)
                }
            }
            Spacer(Modifier.height(10.dp))
            Canvas(Modifier.fillMaxWidth().height(110.dp)) {
                val n = ordered.size.coerceAtLeast(1)
                val slot = size.width / n
                val barW = slot * 0.56f
                for (f in listOf(0f, 0.5f, 1f)) {
                    val y = size.height - f * size.height
                    drawLine(gridColor, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
                }
                ordered.forEachIndexed { i, d ->
                    val x = i * slot + (slot - barW) / 2f
                    val alpha = if (i == ordered.lastIndex) 1f else 0.55f
                    val allowedH = d.allowed.toFloat() / maxTotal * size.height
                    val blockedH = d.blocked.toFloat() / maxTotal * size.height
                    val corner = CornerRadius(5f, 5f)
                    if (allowedH > 0f) drawRoundRect(allowedColor.copy(alpha = alpha), Offset(x, size.height - allowedH), Size(barW, allowedH), corner)
                    if (blockedH > 0f) drawRoundRect(ScreenBad.copy(alpha = alpha), Offset(x, size.height - allowedH - blockedH), Size(barW, blockedH), corner)
                }
            }
            Spacer(Modifier.height(4.dp))
            Row(Modifier.fillMaxWidth()) {
                letters.forEach { l ->
                    Text(l, Modifier.weight(1f), textAlign = TextAlign.Center, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            val today = ordered.lastOrNull()
            if (today != null) {
                Spacer(Modifier.height(6.dp))
                Text(
                    (if (english) "Today: " else "Hoy: ") + fmtBytes(today.allowed) + (if (english) " allowed · " else " permitido · ") + fmtBytes(today.blocked) + (if (english) " blocked" else " bloqueado"),
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** Split of the recent connection history by network (Wi‑Fi, mobile, other). [counts] = network name to connections. */
@Composable
fun NetworkSplitCard(english: Boolean, counts: List<Pair<String, Int>>) {
    val total = counts.sumOf { it.second }.coerceAtLeast(1)
    val palette = listOf(MaterialTheme.colorScheme.primary, ScreenWarn, MaterialTheme.colorScheme.onSurfaceVariant, ScreenOk)
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Text(
                if (english) "CONNECTIONS BY NETWORK" else "CONEXIONES POR RED",
                fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (english) "Based on the recent history list." else "Según el historial reciente.",
                fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            if (counts.isEmpty()) {
                Text(if (english) "No recent connections." else "Sin conexiones recientes.", fontSize = 12.sp)
            } else {
                Row(Modifier.fillMaxWidth().height(10.dp).clip(RoundedCornerShape(5.dp)), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    counts.forEachIndexed { i, (_, c) ->
                        Box(Modifier.weight(c.toFloat().coerceAtLeast(0.01f)).height(10.dp).background(palette[i % palette.size]))
                    }
                }
                Spacer(Modifier.height(8.dp))
                counts.forEachIndexed { i, (name, c) ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(palette[i % palette.size]))
                        Spacer(Modifier.width(6.dp))
                        Text(name, fontSize = 12.sp, modifier = Modifier.weight(1f))
                        Text("$c · ${c * 100 / total}%", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}
