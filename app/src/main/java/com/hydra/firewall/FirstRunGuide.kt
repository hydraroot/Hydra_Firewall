package com.hydra.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Three short steps shown once, so someone who knows nothing about firewalls understands what Hydra does,
 * what the "allow / block" question means and where to look when the antivirus flags something.
 * The last step picks Normal (default) or Advanced mode. [onFinish] receives true when Advanced was chosen.
 */
@Composable
fun FirstRunGuide(english: Boolean, onFinish: (advanced: Boolean) -> Unit) {
    var page by remember { mutableStateOf(0) }
    fun t(es: String, en: String) = if (english) en else es
    val titles = listOf(
        t("Qué hace Hydra", "What Hydra does"),
        t("Cuando una app quiere conectarse", "When an app wants to connect"),
        t("Seguridad y modo de uso", "Security and how to use it")
    )
    val bodies = listOf(
        t(
            "Hydra decide qué apps pueden usar Internet. Para empezar, tocá el interruptor grande de Inicio. Android te va a pedir permiso para la VPN: es solo para que Hydra pueda filtrar.",
            "Hydra decides which apps can use the Internet. To start, tap the big switch on Home. Android will ask permission for the VPN: it is only so Hydra can filter."
        ),
        t(
            "La primera vez que una app nueva intenta conectarse, Hydra te pregunta: PERMITIR o BLOQUEAR. Si no la conocés, bloqueala: podés cambiarlo cuando quieras en Apps.",
            "The first time a new app tries to connect, Hydra asks: ALLOW or BLOCK. If you do not recognize it, block it: you can change it any time in Apps."
        ),
        t(
            "En Seguridad, Hydra revisa tus apps buscando malware conocido. Si marca alguna, leé el motivo, buscala en Google y elegí: Desinstalar o Ignorar. Hydra nunca borra nada sola. Podés usar el modo Normal (simple) o el Avanzado (más herramientas); se cambia en Ajustes.",
            "In Security, Hydra checks your apps for known malware. If it flags one, read the reason, search it on Google and choose: Uninstall or Ignore. Hydra never removes anything by itself. You can use Normal mode (simple) or Advanced (more tools); change it in Settings."
        )
    )
    AlertDialog(
        onDismissRequest = { onFinish(false) },
        title = { Text(titles[page]) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(bodies[page], style = MaterialTheme.typography.bodyMedium)
                Text("${page + 1} / 3", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = {
            if (page < 2) {
                Button(onClick = { page++ }) { Text(t("Siguiente", "Next")) }
            } else {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Button(modifier = Modifier.fillMaxWidth(), onClick = { onFinish(false) }) { Text(t("Modo Normal (recomendado)", "Normal mode (recommended)")) }
                    OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { onFinish(true) }) { Text(t("Modo Avanzado", "Advanced mode")) }
                }
            }
        },
        dismissButton = {
            if (page < 2) TextButton(onClick = { onFinish(false) }) { Text(t("Omitir", "Skip")) }
        }
    )
}
