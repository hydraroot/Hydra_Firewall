package com.hydra.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.ConnectionExplainer

/** Lista "¿Por qué se conecta?" (punto 4). La lógica y los textos viven en [ConnectionExplainer] (testeada). */
@Composable
fun ConnectionWhyBlock(reasons: List<ConnectionExplainer.Reason>, english: Boolean, modifier: Modifier = Modifier) {
    if (reasons.isEmpty()) return
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(if (english) "Why is it connecting?" else "¿Por qué se conecta?", style = MaterialTheme.typography.titleSmall)
        reasons.forEach { r ->
            val mark = when (r.level) {
                ConnectionExplainer.Level.DANGER -> "⛔ "
                ConnectionExplainer.Level.WARNING -> "⚠ "
                ConnectionExplainer.Level.NOTICE -> "• "
                ConnectionExplainer.Level.INFO -> "· "
            }
            val color = when (r.level) {
                ConnectionExplainer.Level.DANGER, ConnectionExplainer.Level.WARNING -> MaterialTheme.colorScheme.error
                ConnectionExplainer.Level.NOTICE -> MaterialTheme.colorScheme.onSurface
                ConnectionExplainer.Level.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(mark + r.text(english), style = MaterialTheme.typography.bodySmall, color = color)
        }
    }
}

/**
 * Versión compacta para el aviso de primera conexión: solo aparece si hay una señal de AVISO grave o PELIGRO
 * (para no ensuciar el diálogo en el caso normal).
 */
@Composable
fun ConnectionWhyAlert(reasons: List<ConnectionExplainer.Reason>, english: Boolean, modifier: Modifier = Modifier) {
    val serious = reasons.filter { it.level == ConnectionExplainer.Level.DANGER || it.level == ConnectionExplainer.Level.WARNING }
    if (serious.isEmpty()) return
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        serious.take(2).forEach { r ->
            Text(
                (if (r.level == ConnectionExplainer.Level.DANGER) "⛔ " else "⚠ ") + r.text(english),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}
