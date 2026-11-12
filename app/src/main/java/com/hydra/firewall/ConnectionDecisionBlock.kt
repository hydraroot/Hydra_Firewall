package com.hydra.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.ConnectionHistory

/** Shows the historical cause saved by the packet policy, not a guess based on current settings. */
@Composable
fun ConnectionDecisionBlock(record: ConnectionHistory.Record, english: Boolean, modifier: Modifier = Modifier) {
    val explanation = ConnectionDecisionText.explanation(record.reasonCode, blocked = !record.allowed, english = english)
    val detail = record.reasonDetail?.takeIf { it.isNotBlank() }
    val normalizedDetail = detail?.lowercase().orEmpty()
    val isFirebasePerformanceLogging = normalizedDetail.contains("firebaselogging.googleapis.com")
    val isThreat = record.reasonCode?.contains("THREAT") == true
    val category = when {
        isThreat -> if (english) "CONFIRMED THREAT MATCH" else "COINCIDENCIA DE AMENAZA CONFIRMADA"
        isFirebasePerformanceLogging && record.reasonCode in setOf("AD_TRACKER_BLOCKLIST", "QUIC_BLOCKLIST_DOMAIN") ->
            if (english) "KNOWN TELEMETRY / PERFORMANCE LOGGING" else "TELEMETRÍA / REGISTRO DE RENDIMIENTO CONOCIDO"
        record.reasonCode in setOf("AD_TRACKER_BLOCKLIST", "QUIC_BLOCKLIST_DOMAIN") ->
            if (english) "PUBLIC ADS / TRACKER LIST MATCH" else "COINCIDENCIA EN LISTA PÚBLICA DE ANUNCIOS / RASTREO"
        record.reasonCode in setOf("CUSTOM_DOMAIN_BLOCK", "QUIC_CUSTOM_DOMAIN") -> if (english) "CUSTOM DOMAIN RULE" else "REGLA DE DOMINIO PERSONALIZADA"
        record.reasonCode in setOf("USER_CONNECTION_EXCEPTION", "USER_DOMAIN_EXCEPTION", "USER_IP_EXCEPTION") -> if (english) "USER EXCEPTION" else "EXCEPCIÓN DEL USUARIO"
        record.reasonCode == "USER_IP_BLOCK" -> if (english) "IP BLOCK RULE" else "REGLA DE BLOQUEO IP"
        else -> if (english) "FIREWALL POLICY" else "POLÍTICA DEL FIREWALL"
    }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(category, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
        Text(
            if (english) "Decision reason" else "Motivo de la decisión",
            style = MaterialTheme.typography.titleSmall
        )
        Text(explanation, style = MaterialTheme.typography.bodySmall)
        detail?.let {
            Text(
                (if (english) "Recorded match: " else "Coincidencia registrada: ") + it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (isFirebasePerformanceLogging && !isThreat) {
            Text(
                if (english) "Known purpose: Firebase Performance Monitoring can send performance log data to this endpoint. A blocklist match alone does not mean malware or prove that this exact request is malicious."
                else "Función conocida: Firebase Performance Monitoring puede enviar datos de registro de rendimiento a este destino. Coincidir con una lista no significa por sí solo que sea malware ni demuestra que esta solicitud concreta sea maliciosa.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        } else if (record.reasonCode in setOf("AD_TRACKER_BLOCKLIST", "QUIC_BLOCKLIST_DOMAIN")) {
            Text(
                if (english) "This event confirms membership in the active public blocklist; it does not independently prove the destination's exact purpose."
                else "Este evento confirma que el dominio figura en la lista pública activa; por sí solo no demuestra cuál es su función exacta.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
