package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.ConnectionExceptionStore
import com.hydra.firewall.vpn.ConnectionExceptionStore.Entry
import java.text.DateFormat
import java.util.Date

@Composable
fun ConnectionExceptionsPanel(
    context: Context,
    english: Boolean,
    version: Int,
    onChanged: () -> Unit
) {
    var entries by remember(version) { mutableStateOf(ConnectionExceptionStore.snapshot(context)) }

    fun refresh() {
        entries = ConnectionExceptionStore.snapshot(context)
        onChanged()
    }

    LaunchedEffect(version) { entries = ConnectionExceptionStore.snapshot(context) }

    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(7.dp)) {
        Text(
            if (english) "These exceptions are local to this device. Threat signatures and Block All are never overridden." 
            else "Estas excepciones quedan guardadas en este dispositivo. Nunca anulan firmas de amenazas ni Bloquear todo.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (entries.isEmpty()) {
            Text(
                if (english) "No connection exceptions." else "No hay excepciones de conexiones.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            entries.forEach { entry ->
                Column(Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                entry.domain ?: "${entry.protocol} ${entry.ip}:${entry.port}",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                "${com.hydra.firewall.vpn.AppNames.label(entry.uid, entry.packageName)} · UID ${entry.uid}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                if (entry.expiresAt == 0L) {
                                    if (english) "Permanent · this package + UID only" else "Permanente · solo este paquete + UID"
                                } else {
                                    (if (english) "Expires " else "Vence ") + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(entry.expiresAt))
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                        Spacer(Modifier.width(6.dp))
                        TextButton(onClick = { ConnectionExceptionStore.remove(context, entry); refresh() }) {
                            Text(if (english) "Remove" else "Quitar")
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}
