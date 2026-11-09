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
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
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
    }
}
