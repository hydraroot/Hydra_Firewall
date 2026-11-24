package com.hydra.firewall

import android.Manifest
import com.hydra.firewall.ui.theme.HydraCard
import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.os.Bundle
import android.os.Process
import android.os.Handler
import android.os.Looper
import android.widget.ImageView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.Canvas
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.hydra.firewall.ui.theme.FirewallLocalTheme
import com.hydra.firewall.security.AppIntegrity
import com.hydra.firewall.security.ProtectionStatus
import com.hydra.firewall.vpn.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.Locale

@Composable
internal fun LiveTrafficChart(history: List<Pair<Float, Float>>) {
    val allowedColor = Color(0xFF2E7D32)
    val blockedColor = Color(0xFFC62828)
    val language = AppSettings(LocalContext.current).language
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).background(allowedColor, shape = androidx.compose.foundation.shape.CircleShape))
            Spacer(Modifier.width(4.dp)); Text(if (language.isEnglish()) "Allowed" else "Permitido", style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.width(10.dp))
            Box(Modifier.size(8.dp).background(blockedColor, shape = androidx.compose.foundation.shape.CircleShape))
            Spacer(Modifier.width(4.dp)); Text(if (language.isEnglish()) "Blocked" else "Bloqueado", style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.width(10.dp))
            Text(if (language.isEnglish()) "MB per interval" else "MB por intervalo", style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(4.dp))
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(128.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(6.dp)
        ) {
            val allowedMax = history.maxOfOrNull { it.first }?.coerceAtLeast(0.01f) ?: 0.01f
            val blockedMax = history.maxOfOrNull { it.second }?.coerceAtLeast(0.01f) ?: 0.01f
            val maxVal = maxOf(allowedMax, blockedMax)
            if (history.size >= 2) {
                val stepX = size.width / (history.size - 1).coerceAtLeast(1)
                fun pointY(v: Float): Float = size.height - (v / maxVal) * size.height
                fun pathFor(pick: (Pair<Float, Float>) -> Float) = androidx.compose.ui.graphics.Path().apply {
                    history.forEachIndexed { i, v ->
                        val x = i * stepX
                        val y = pointY(pick(v))
                        if (i == 0) moveTo(x, y) else lineTo(x, y)
                    }
                }
                drawPath(pathFor { it.first }, color = allowedColor, style = Stroke(width = 2.2f))
                drawPath(pathFor { it.second }, color = blockedColor, style = Stroke(width = 2.2f))

                val paint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
                    textSize = 18f
                    typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
                }
                fun drawPeakLabel(index: Int, value: Float, color: Color, upward: Boolean) {
                    if (value <= 0f) return
                    val x = (index * stepX).coerceIn(4f, size.width - 44f)
                    val y = (pointY(value) + if (upward) -4f else 18f).coerceIn(12f, size.height - 2f)
                    paint.color = android.graphics.Color.WHITE
                    val label = formatTrafficMb(value)
                    drawContext.canvas.nativeCanvas.drawText(label, x, y, paint)
                }
                for (i in 1 until history.lastIndex) {
                    val a = history[i].first
                    if (a > 0f && a >= history[i-1].first && a >= history[i+1].first) drawPeakLabel(i, a, allowedColor, true)
                    val b = history[i].second
                    if (b > 0f && b >= history[i-1].second && b >= history[i+1].second) drawPeakLabel(i, b, blockedColor, false)
                }
            }
        }
    }
}

@Composable
internal fun TrafficTotalsBarChart(allowedBytes: Long, blockedBytes: Long) {
    val context = LocalContext.current
    val allowedColor = Color(0xFF2E7D32)
    val blockedColor = Color(0xFFC62828)
    val max = maxOf(allowedBytes, blockedBytes, 1L).toDouble()
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(if (AppSettings(context).language.isEnglish()) "Traffic volume" else "Volumen de tráfico", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(6.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(8.dp).height(24.dp).background(allowedColor, androidx.compose.foundation.shape.RoundedCornerShape(4.dp)))
            Spacer(Modifier.width(6.dp))
            Text(if (AppSettings(context).language.isEnglish()) "Allowed" else "Permitido", Modifier.width(72.dp), style = MaterialTheme.typography.bodySmall)
            Box(Modifier.weight(1f).height(24.dp).clip(androidx.compose.foundation.shape.RoundedCornerShape(5.dp)).background(MaterialTheme.colorScheme.surfaceVariant)) {
                Box(Modifier.fillMaxHeight().fillMaxWidth((allowedBytes.toDouble() / max).toFloat()).background(allowedColor))
            }
            Spacer(Modifier.width(8.dp))
            Text(formatBytes(allowedBytes), style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(6.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(8.dp).height(24.dp).background(blockedColor, androidx.compose.foundation.shape.RoundedCornerShape(4.dp)))
            Spacer(Modifier.width(6.dp))
            Text(if (AppSettings(context).language.isEnglish()) "Blocked" else "Bloqueado", Modifier.width(72.dp), style = MaterialTheme.typography.bodySmall)
            Box(Modifier.weight(1f).height(24.dp).clip(androidx.compose.foundation.shape.RoundedCornerShape(5.dp)).background(MaterialTheme.colorScheme.surfaceVariant)) {
                Box(Modifier.fillMaxHeight().fillMaxWidth((blockedBytes.toDouble() / max).toFloat()).background(blockedColor))
            }
            Spacer(Modifier.width(8.dp))
            Text(formatBytes(blockedBytes), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
internal fun TrafficUsageChart(stats: List<TrafficStatsStore.Snapshot>) {
    val top = stats.map { it to (it.txBytes + it.rxBytes) }.sortedByDescending { it.second }.take(6)
    val max = top.maxOfOrNull { it.second }?.coerceAtLeast(1L) ?: 1L
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        if (top.isEmpty()) {
            Text(tr(LocalContext.current,"no_data"), style = MaterialTheme.typography.bodySmall)
        } else {
            top.forEach { (s, total) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(com.hydra.firewall.vpn.AppNames.label(s.uid, s.packageName).take(18), Modifier.width(140.dp), style = MaterialTheme.typography.bodySmall)
                    LinearProgressIndicator(progress = { (total.toDouble() / max.toDouble()).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.weight(1f))
                    Text(formatBytes(total), Modifier.padding(start = 8.dp), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
internal fun TrafficAnalyzerScreen(context: Context) {
    val english = AppSettings(context).language.isEnglish()
    var enabled by remember { mutableStateOf(TrafficAnalyzerStore.isEnabled()) }
    var events by remember { mutableStateOf(TrafficAnalyzerStore.snapshot()) }
    var filter by remember { mutableStateOf("ALL") }
    var search by remember { mutableStateOf("") }
    var selectedEvent by remember { mutableStateOf<TrafficAnalyzerStore.Event?>(null) }
    val ipBlockStore = remember { IpBlockStore(context.applicationContext) }
    var blockedIps by remember { mutableStateOf(ipBlockStore.getBlocked().toSet()) }

    LaunchedEffect(enabled) {
        while (enabled) {
            events = TrafficAnalyzerStore.snapshot()
            delay(700)
        }
    }

    fun matchesSearch(e: TrafficAnalyzerStore.Event): Boolean {
        val q = search.trim().lowercase(Locale.US)
        if (q.isEmpty()) return true
        val text = listOfNotNull(e.packageName, e.domain, e.destination, e.protocol, e.kind, e.port.toString()).joinToString(" ").lowercase(Locale.US)
        return text.contains(q)
    }

    val filtered = events.filter { e ->
        val typeOk = when (filter) {
            "APP" -> !e.packageName.isNullOrBlank()
            "DNS" -> e.protocol == "DNS"
            "BLOCKED" -> e.kind.contains("BLOCK", true)
            else -> true
        }
        typeOk && matchesSearch(e)
    }

    val totalBytes = filtered.sumOf { it.bytes.toLong() }
    val sentBytes = filtered.filter { it.kind == "C2S_DATA" }.sumOf { it.bytes.toLong() }
    val receivedBytes = filtered.filter { it.kind == "S2C_DATA" }.sumOf { it.bytes.toLong() }
    val dnsCount = filtered.count { it.protocol == "DNS" }
    val blockedCount = filtered.count { it.kind.contains("BLOCK", true) }
    val tcpCount = filtered.count { it.protocol == "TCP" }
    val udpCount = filtered.count { it.protocol == "UDP" }
    val quicCount = filtered.count { it.protocol == "UDP" && it.port == 443 }

    val appCounts = filtered.filter { !it.packageName.isNullOrBlank() }
        .groupingBy { it.packageName!! }.eachCount().entries.sortedByDescending { it.value }.take(12)
    val domainCounts = filtered.filter { !it.domain.isNullOrBlank() }
        .groupingBy { it.domain!! }.eachCount().entries.sortedByDescending { it.value }.take(12)
    val endpointCounts = filtered.filter { it.protocol != "DNS" }
        .groupingBy { "${it.destination}:${it.port}" }.eachCount().entries.sortedByDescending { it.value }.take(12)

    fun appLabel(pkg: String?): String {
        if (pkg.isNullOrBlank()) return if (english) "Unknown app" else "Aplicación desconocida"
        return runCatching {
            val info = context.packageManager.getApplicationInfo(pkg, 0)
            context.packageManager.getApplicationLabel(info).toString()
        }.getOrDefault(pkg)
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 10.dp, vertical = 6.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Column(Modifier.weight(1f)) {
                Text(if (english) "Network analyzer" else "Analizador de red", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(
                    if (english) "Live metadata: apps, DNS, destinations and traffic. No payloads are stored."
                    else "Metadatos en vivo: apps, DNS, destinos y tráfico. No se guardan contenidos.",
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (english) "CAPTURE" else "CAPTURA", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.width(4.dp))
                Switch(checked = enabled, onCheckedChange = {
                    enabled = it
                    TrafficAnalyzerStore.setEnabled(context, it)
                    events = emptyList()
                    selectedEvent = null
                }, modifier = Modifier.height(28.dp).scale(0.82f))
            }
        }

        Spacer(Modifier.height(7.dp))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            listOf(
                "ALL" to if (english) "All" else "Todo",
                "APP" to if (english) "Apps" else "Apps",
                "DNS" to "DNS",
                "BLOCKED" to if (english) "Blocked" else "Bloqueados"
            ).forEach { (key, label) ->
                HydraChoiceButton(filter == key, label, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = { filter = key }, modifier = Modifier.height(30.dp))
            }
            HydraChoiceButton(false, if (english) "Clear" else "Borrar", Color(0xFFB83A46), Color.White, onClick = {
                TrafficAnalyzerStore.clear(); events = emptyList(); selectedEvent = null
            }, modifier = Modifier.height(30.dp))
        }

        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            singleLine = true,
            label = { Text(if (english) "Search app, domain, IP or port" else "Buscar app, dominio, IP o puerto") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(fontSize = 12.sp)
        )

        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            AnalyzerMetric(if (english) "Events" else "Eventos", filtered.size.toString())
            AnalyzerMetric("DNS", dnsCount.toString())
            AnalyzerMetric(if (english) "Blocked" else "Bloqueados", blockedCount.toString())
            AnalyzerMetric("TCP/UDP", "$tcpCount/$udpCount")
            AnalyzerMetric("QUIC", quicCount.toString())
        }
        Spacer(Modifier.height(5.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            AnalyzerMetric("↑", formatAnalyzerBytes(sentBytes))
            AnalyzerMetric("↓", formatAnalyzerBytes(receivedBytes))
            AnalyzerMetric(if (english) "Total" else "Total", formatAnalyzerBytes(totalBytes))
        }

        if (!enabled) {
            Spacer(Modifier.height(10.dp))
            AnalyzerSection(if (english) "Ready" else "Listo") {
                Text(if (english) "Enable Capture and use the phone normally. Hydra will show activity here in real time."
                     else "Activá Captura y usá el teléfono normalmente. Hydra mostrará la actividad en tiempo real.", fontSize = 12.sp)
            }
        } else {
            AnalyzerSection(if (english) "Applications" else "Aplicaciones") {
                if (appCounts.isEmpty()) Text("—", fontSize = 12.sp)
                appCounts.forEach { (pkg, count) ->
                    val appEvents = filtered.filter { it.packageName == pkg }
                    val bytes = appEvents.sumOf { it.bytes.toLong() }
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(appLabel(pkg), fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
                        Text("${formatAnalyzerBytes(bytes)}  •  $count", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            AnalyzerSection(if (english) "DNS domains" else "Dominios DNS") {
                if (domainCounts.isEmpty()) Text("—", fontSize = 12.sp)
                domainCounts.forEach { (domain, count) -> AnalyzerLine(domain, count.toString()) }
            }

            AnalyzerSection(if (english) "Top destinations" else "Principales destinos") {
                if (endpointCounts.isEmpty()) Text("—", fontSize = 12.sp)
                endpointCounts.forEach { (endpoint, count) -> AnalyzerLine(endpoint, count.toString()) }
            }

            AnalyzerSection(if (english) "Live activity" else "Actividad en vivo") {
                filtered.take(50).forEach { e ->
                    val app = appLabel(e.packageName)
                    val status = if (e.kind.contains("BLOCK", true)) " ⛔" else ""
                    Row(
                        Modifier.fillMaxWidth().clickable { selectedEvent = e }.padding(vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("${e.time}  $app$status", fontSize = 10.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            Text("${e.protocol}  ${e.destination}:${e.port}  ${e.kind}${if (e.bytes > 0) "  ${formatAnalyzerBytes(e.bytes.toLong())}" else ""}", fontSize = 9.sp, maxLines = 1, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        selectedEvent?.let { e ->
            AnalyzerSection(if (english) "Connection details" else "Detalles de conexión") {
                Text(if (english) "App: ${appLabel(e.packageName)}" else "App: ${appLabel(e.packageName)}", fontSize = 11.sp)
                Text("Package: ${e.packageName ?: "—"}", fontSize = 10.sp)
                Text("${e.protocol}  ${e.destination}:${e.port}", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text("${e.kind}  ${formatAnalyzerBytes(e.bytes.toLong())}", fontSize = 10.sp)
                if (!e.domain.isNullOrBlank()) Text("DNS: ${e.domain}", fontSize = 10.sp)
                if (e.destination != "?" && runCatching { java.net.InetAddress.getByName(e.destination) }.isSuccess) {
                    val isBlocked = blockedIps.contains(e.destination)
                    val isException = ipBlockStore.isAllowedForUid(e.uid, e.destination)
                    val isPolicyBlocked = e.kind.contains("BLOCK", true)
                    Spacer(Modifier.height(5.dp))
                    val label = when {
                        isBlocked -> if (english) "Unblock IP" else "Desbloquear IP"
                        isException -> if (english) "Remove IP allow" else "Quitar permiso IP"
                        isPolicyBlocked -> if (english) "Allow IP" else "Permitir IP"
                        else -> if (english) "Block IP" else "Bloquear IP"
                    }
                    HydraChoiceButton(isBlocked || isException, label, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = {
                        when {
                            isBlocked -> ipBlockStore.remove(e.destination)
                            isException -> ipBlockStore.removeAllowedForUid(e.uid, e.destination)
                            isPolicyBlocked -> ipBlockStore.allowForUid(e.uid, e.destination)
                            else -> ipBlockStore.add(e.destination)
                        }
                        blockedIps = ipBlockStore.getBlocked().toSet()
                        notifyRulesChanged(context)
                    }, modifier = Modifier.height(30.dp))
                }
            }
        }
    }
}

@Composable
internal fun AnalyzerMetric(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontWeight = FontWeight.Bold, fontSize = 12.sp)
        Text(label, fontSize = 8.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
internal fun AnalyzerSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(title, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 7.dp, bottom = 3.dp))
    Surface(shape = RoundedCornerShape(10.dp), tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(8.dp), content = content)
    }
    Spacer(Modifier.height(4.dp))
}

@Composable
internal fun AnalyzerLine(left: String, right: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(left, fontSize = 10.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Text(right, fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 8.dp))
    }
}
