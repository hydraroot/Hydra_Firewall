package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.ui.theme.HydraCard
import com.hydra.firewall.vpn.AlertStore
import com.hydra.firewall.vpn.IpBlockStore
import kotlinx.coroutines.delay

private val AlertRed = Color(0xFFF87171)
private val AlertAmber = Color(0xFFFBBF24)

/**
 * Botón de acción reversible: al tocarlo ejecuta [onAction] y durante 5 s pasa a "Deshacer (n)". Si se toca, llama a
 * [onUndo]; si se vence la ventana, llama a [onFinish]. Si [initiallyArmed] es true arranca ya en cuenta regresiva.
 */
@Composable
fun UndoActionButton(
    english: Boolean,
    actionLabel: String,
    color: Color,
    onAction: () -> Unit,
    onUndo: () -> Unit,
    onFinish: () -> Unit = {}
) {
    var armed by remember { mutableStateOf(false) }
    var left by remember { mutableStateOf(5) }
    LaunchedEffect(armed) {
        if (armed) {
            var s = (AlertStore.UNDO_WINDOW_MS / 1000L).toInt()
            while (s > 0) {
                left = s
                delay(1000L)
                s--
            }
            armed = false
            onFinish()
        }
    }
    val label = if (armed) (if (english) "Undo ($left)" else "Deshacer ($left)") else actionLabel
    val c = if (armed) MaterialTheme.colorScheme.primary else color
    Text(
        label,
        color = if (armed) Color.White else c,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(if (armed) c else c.copy(alpha = 0.16f))
            .clickable {
                if (armed) {
                    armed = false
                    onUndo()
                } else {
                    armed = true
                    onAction()
                }
            }
            .padding(horizontal = 14.dp, vertical = 8.dp)
    )
}

/** Tarjeta de Inicio: avisos "la app X se conecta a Y — ¿bloqueamos?". No se dibuja si no hay nada. */
@Composable
fun HomeAlertsCard(context: Context, english: Boolean) {
    var alerts by remember { mutableStateOf(AlertStore.visibleOnHome(context)) }
    var rev by remember { mutableStateOf(0) }
    LaunchedEffect(rev) {
        while (true) {
            alerts = AlertStore.visibleOnHome(context)
            delay(1500L)
        }
    }
    if (alerts.isEmpty()) return
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(21.dp)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp)) {
            Text(
                (if (english) "ALERTS" else "AVISOS") + " · ${alerts.size}",
                style = MaterialTheme.typography.labelSmall,
                color = AlertAmber,
                fontWeight = FontWeight.Bold
            )
            alerts.forEach { a ->
                key(a.id) {
                    Column(Modifier.fillMaxWidth().padding(top = 8.dp)) {
                        Text(
                            if (english) "${a.appLabel} connects to" else "${a.appLabel} se conecta a",
                            fontWeight = FontWeight.SemiBold, fontSize = 13.sp
                        )
                        Text(
                            a.host, fontFamily = FontFamily.Monospace, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            when (a.reason) {
                                AlertStore.Reason.THREAT -> if (english) "Known threat destination. Block it?" else "Destino conocido como amenaza. ¿Lo bloqueamos?"
                                AlertStore.Reason.NEW_DESTINATION -> if (english) "New destination for this app. Block it?" else "Destino nuevo para esta app. ¿Lo bloqueamos?"
                            },
                            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(6.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            UndoActionButton(
                                english = english,
                                actionLabel = if (english) "Block" else "Bloquear",
                                color = AlertRed,
                                onAction = { AlertStore.block(context, a.id); notifyRulesChanged(context) },
                                onUndo = { AlertStore.unblock(context, a.id, AlertStore.Status.PENDING); notifyRulesChanged(context); rev++ },
                                onFinish = { rev++ }
                            )
                            if (a.status == AlertStore.Status.PENDING) {
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    if (english) "Ignore" else "Ignorar",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold, fontSize = 12.sp,
                                    modifier = Modifier.clip(RoundedCornerShape(50)).clickable { AlertStore.ignore(context, a.id); rev++ }
                                        .padding(horizontal = 12.dp, vertical = 8.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private data class BlockedEntry(val key: String, val title: String, val sub: String, val ip: String, val alertId: Long?)

/**
 * Sección de Reglas: todo lo que Hydra bloqueó por aviso o por IP manual, con "Desbloquear" que durante 5 s pasa a
 * "Deshacer". Si no hay nada bloqueado muestra un aviso; "Limpiar" desbloquea todo tras confirmar.
 */
@Composable
fun BlockedDestinationsSection(context: Context, english: Boolean) {
    var rev by remember { mutableStateOf(0) }
    var held by remember { mutableStateOf(mapOf<String, BlockedEntry>()) }
    val entries = remember(rev) {
        val fromAlerts = AlertStore.blocked(context).map {
            BlockedEntry("a${it.id}", it.host, "${it.appLabel} · ${it.ip}", it.ip, it.id)
        }
        val alertIps = fromAlerts.map { it.ip }.toSet()
        val manual = IpBlockStore(context).getBlocked().filter { it !in alertIps }.map {
            BlockedEntry("m$it", it, if (english) "Blocked manually" else "Bloqueado manualmente", it, null)
        }
        fromAlerts + manual
    }
    val shown = entries + held.values.filter { h -> entries.none { it.key == h.key } }
    var confirmClear by remember { mutableStateOf(false) }
    if (shown.isEmpty()) {
        HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(21.dp)) {
            Text(
                if (english) "No blocked destinations." else "Sin destinos bloqueados.",
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }
    if (confirmClear) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { confirmClear = false },
            title = { Text(if (english) "Clear blocked destinations?" else "¿Limpiar destinos bloqueados?", color = hydraDialogColors().second) },
            text = {
                Text(
                    if (english) "All ${entries.size} blocked destinations will be unblocked." else "Se van a desbloquear los ${entries.size} destinos bloqueados.",
                    color = hydraDialogColors().third
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    entries.forEach { e ->
                        if (e.alertId != null) AlertStore.unblock(context, e.alertId) else IpBlockStore(context).remove(e.ip)
                    }
                    held = emptyMap()
                    confirmClear = false
                    notifyRulesChanged(context)
                    rev++
                }) { Text(if (english) "Unblock all" else "Desbloquear todo") }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(if (english) "Cancel" else "Cancelar") } }
        )
    }
    HydraCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(21.dp)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    (if (english) "BLOCKED DESTINATIONS" else "DESTINOS BLOQUEADOS") + " · ${entries.size}",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = { confirmClear = true }) { Text(if (english) "Clear" else "Limpiar") }
            }
            shown.forEach { e ->
                key(e.key) {
                    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(e.title, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(e.sub, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Spacer(Modifier.width(8.dp))
                        UndoActionButton(
                            english = english,
                            actionLabel = if (english) "Unblock" else "Desbloquear",
                            color = MaterialTheme.colorScheme.primary,
                            onAction = {
                                if (e.alertId != null) AlertStore.unblock(context, e.alertId) else IpBlockStore(context).remove(e.ip)
                                held = held + (e.key to e)
                                notifyRulesChanged(context)
                                rev++
                            },
                            onUndo = {
                                if (e.alertId != null) AlertStore.block(context, e.alertId) else IpBlockStore(context).add(e.ip)
                                held = held - e.key
                                notifyRulesChanged(context)
                                rev++
                            },
                            onFinish = { held = held - e.key; rev++ }
                        )
                    }
                }
            }
        }
    }
}
