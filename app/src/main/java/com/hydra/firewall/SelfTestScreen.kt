package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.vpn.HydraLiveTest
import com.hydra.firewall.vpn.HydraSelfTest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

@Composable
fun SelfTestScreen(context: Context, language: AppLanguage) {
    val en = language == AppLanguage.EN || (language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
    var results by remember { mutableStateOf<List<HydraSelfTest.CheckResult>>(emptyList()) }
    var running by remember { mutableStateOf(false) }
    var ranOnce by remember { mutableStateOf(false) }

    suspend fun run() {
        running = true
        results = withContext(Dispatchers.IO) { HydraSelfTest.runAll(context) }
        running = false
        ranOnce = true
    }

    var liveResults by remember { mutableStateOf<List<HydraSelfTest.CheckResult>>(emptyList()) }
    var liveRunning by remember { mutableStateOf(false) }
    var liveRanOnce by remember { mutableStateOf(false) }
    var showLiveConfirm by remember { mutableStateOf(false) }

    suspend fun runLive() {
        liveRunning = true
        liveResults = withContext(Dispatchers.IO) { HydraLiveTest.run(context) }
        liveRunning = false
        liveRanOnce = true
    }

    LaunchedEffect(Unit) { run() }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Text(
            if (en) "HYDRA diagnostics" else "Diagnóstico de HYDRA",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(4.dp))
        Text(
            if (en)
                "Checks HYDRA's own parsing/logic code and current status. HYDRA excludes this app from its own tunnel, so this cannot prove traffic from other apps is being filtered right now — for that, use the ADB diagnostic log."
            else
                "Revisa el código de parsing/lógica de HYDRA y su estado actual. HYDRA excluye a esta app de su propio túnel, así que esto no prueba que el tráfico de otras apps se esté filtrando en este momento — para eso, usá el log de diagnóstico por ADB.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(10.dp))

        Button(
            onClick = { scope.launch { run() } },
            enabled = !running
        ) {
            Text(
                when {
                    running -> if (en) "Running..." else "Ejecutando..."
                    ranOnce -> if (en) "Run again" else "Volver a probar"
                    else -> if (en) "Run" else "Ejecutar"
                }
            )
        }

        Spacer(Modifier.height(10.dp))

        if (running && results.isEmpty()) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        }

        if (ranOnce) {
            val passCount = results.count { it.status == HydraSelfTest.Status.PASS }
            val warnCount = results.count { it.status == HydraSelfTest.Status.WARN }
            val failCount = results.count { it.status == HydraSelfTest.Status.FAIL }
            Text(
                if (en) "$passCount OK · $warnCount warnings · $failCount failed"
                else "$passCount OK · $warnCount advertencias · $failCount fallidos",
                style = MaterialTheme.typography.titleSmall,
                color = if (failCount > 0) Color(0xFFC62828) else if (warnCount > 0) Color(0xFFD98E1F) else Color(0xFF2E7D32)
            )
            Spacer(Modifier.height(8.dp))
        }

        results.forEach { result ->
            SelfTestRow(result)
            Spacer(Modifier.height(6.dp))
        }

        Spacer(Modifier.height(20.dp))
        HorizontalDivider()
        Spacer(Modifier.height(12.dp))

        Text(
            if (en) "Live connectivity test" else "Prueba de conectividad en vivo",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(4.dp))
        Text(
            if (en)
                "Actually routes HYDRA's own traffic through its tunnel for a few seconds to check a known ad domain, a normal domain, and a real TCP handshake. This briefly interrupts connectivity for the whole device (the VPN restarts twice)."
            else
                "Hace pasar el tráfico de HYDRA por su propio túnel durante unos segundos para probar un dominio de anuncios conocido, un dominio normal y un handshake TCP real. Esto corta brevemente la red de todo el teléfono (la VPN reinicia dos veces).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(10.dp))

        Button(
            onClick = { showLiveConfirm = true },
            enabled = !liveRunning && !running
        ) {
            Text(
                when {
                    liveRunning -> if (en) "Running (network may drop briefly)..." else "Ejecutando (la red puede cortarse un instante)..."
                    liveRanOnce -> if (en) "Run live test again" else "Volver a probar en vivo"
                    else -> if (en) "Run live test" else "Ejecutar prueba en vivo"
                }
            )
        }

        if (showLiveConfirm) {
            AlertDialog(
                onDismissRequest = { showLiveConfirm = false },
                title = { Text(if (en) "Run live test?" else "¿Ejecutar prueba en vivo?") },
                text = {
                    Text(
                        if (en) "This will briefly interrupt network connectivity for the whole device while HYDRA restarts twice. Continue?"
                        else "Esto va a cortar brevemente la conexión de todo el teléfono mientras HYDRA reinicia dos veces. ¿Continuar?"
                    )
                },
                confirmButton = {
                    TextButton(onClick = { showLiveConfirm = false; scope.launch { runLive() } }) {
                        Text(if (en) "Continue" else "Continuar")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showLiveConfirm = false }) { Text(if (en) "Cancel" else "Cancelar") }
                }
            )
        }

        Spacer(Modifier.height(10.dp))
        if (liveRunning) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
        }

        if (liveRanOnce) {
            val livePass = liveResults.count { it.status == HydraSelfTest.Status.PASS }
            val liveFail = liveResults.count { it.status == HydraSelfTest.Status.FAIL }
            Text(
                if (en) "$livePass OK · $liveFail failed" else "$livePass OK · $liveFail fallidos",
                style = MaterialTheme.typography.titleSmall,
                color = if (liveFail > 0) Color(0xFFC62828) else Color(0xFF2E7D32)
            )
            Spacer(Modifier.height(8.dp))
        }

        liveResults.forEach { result ->
            SelfTestRow(result)
            Spacer(Modifier.height(6.dp))
        }
    }
}

@Composable
private fun SelfTestRow(result: HydraSelfTest.CheckResult) {
    val (color, badge) = when (result.status) {
        HydraSelfTest.Status.PASS -> Color(0xFF2E7D32) to "OK"
        HydraSelfTest.Status.WARN -> Color(0xFFD98E1F) to "WARN"
        HydraSelfTest.Status.FAIL -> Color(0xFFC62828) to "FAIL"
    }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().padding(10.dp)) {
            Box(
                modifier = Modifier
                    .padding(top = 2.dp, end = 8.dp)
            ) {
                Text(
                    badge,
                    color = color,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp
                )
            }
            Column(Modifier.weight(1f)) {
                Text(result.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                Text(result.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
