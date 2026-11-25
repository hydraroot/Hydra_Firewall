package com.hydra.firewall

import com.hydra.firewall.ui.theme.HydraCard
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.unit.dp
import com.hydra.firewall.vpn.*

internal const val HYDRA_REPOSITORY_URL = "https://github.com/hydraroot/Hydra_Firewall"

internal const val HYDRA_LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"

internal const val CAFECITO_URL = "https://cafecito.app/hydraroot"

@Composable
internal fun AboutScreen(context: Context) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(14.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        androidx.compose.foundation.Image(
            painter = androidx.compose.ui.res.painterResource(com.hydra.firewall.R.drawable.hydra_tree),
            contentDescription = "Hydra Firewall",
            modifier = Modifier.size(96.dp).padding(2.dp).clip(CircleShape)
        )
        Text("Hydra Firewall", style = MaterialTheme.typography.headlineSmall)
        Text("${tr(context, "version")}: ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(6.dp))
        Text(tr(context, "creator"), style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(12.dp))
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "about_summary"), style = MaterialTheme.typography.bodyMedium)
                Text(tr(context, "about_features"), style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "license"), style = MaterialTheme.typography.titleSmall)
                Text(tr(context, "license_gpl"), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(HYDRA_LICENSE_URL))) }) {
                    Text(tr(context, "view_license"))
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "repository"), style = MaterialTheme.typography.titleSmall)
                Text(HYDRA_REPOSITORY_URL, style = MaterialTheme.typography.bodySmall)
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(HYDRA_REPOSITORY_URL))) }) {
                    Text(tr(context, "open_repository"))
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "block_ads_title"), style = MaterialTheme.typography.titleSmall)
                Text(tr(context, "block_ads_attribution"), style = MaterialTheme.typography.bodySmall)
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DomainBlockStore.SOURCE_PAGE_URL))) }) {
                    Text(DomainBlockStore.SOURCE_PAGE_URL)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        HydraCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "donate"), style = MaterialTheme.typography.titleSmall)
                Text(tr(context, "donate_pending"), style = MaterialTheme.typography.bodySmall)
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(CAFECITO_URL))) }) {
                    Text(tr(context, "donate_button"))
                }
            }
        }
        Spacer(Modifier.height(20.dp))
    }
}
