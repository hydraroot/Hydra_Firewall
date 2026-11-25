package com.hydra.firewall

import com.hydra.firewall.ui.theme.HydraCard
import android.content.Context
import android.provider.Settings
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.hydra.firewall.security.AppIntegrity
import com.hydra.firewall.security.ProtectionStatus
import com.hydra.firewall.vpn.*

@Composable
internal fun CustomProtectionEditorDialog(
    context: Context,
    app: AppEntry,
    store: CustomProtectionProfileStore,
    ruleStore: RuleStore,
    english: Boolean,
    onDismiss: () -> Unit,
    onApply: (CustomProtectionProfileStore.Profile) -> Unit
) {
    val initial = remember(app.uid) { store.get(app.uid) }
    var profile by remember(app.uid) { mutableStateOf(initial) }
    val rule = remember(app.uid) { ruleStore.getRule(app.uid) }

    AlertDialog(
        containerColor = hydraDialogColors().first,
        titleContentColor = hydraDialogColors().second,
        textContentColor = hydraDialogColors().third,
        onDismissRequest = onDismiss,
        title = {
            Column {
                Text(if (english) "PERSONALIZED" else "PERSONALIZADO")
                Text(app.label, style = MaterialTheme.typography.titleSmall)
            }
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    if (english)
                        "Choose which optional Hydra protections this app uses. Network access (Wi‑Fi/Mobile) remains a separate rule."
                    else
                        "Elegí qué protecciones opcionales de Hydra usa esta app. El acceso de red (Wi‑Fi/Móvil) sigue siendo una regla separada.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(6.dp))
                CustomProtectionChecklist(
                    profile = profile,
                    english = english,
                    onProfileChange = { profile = it }
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    if (english) "Wi‑Fi: ${if (rule.wifiAllowed) "ALLOW" else "BLOCK"} · Mobile: ${if (rule.mobileAllowed) "ALLOW" else "BLOCK"}"
                    else "Wi‑Fi: ${if (rule.wifiAllowed) "PERMITIR" else "BLOQUEAR"} · Móvil: ${if (rule.mobileAllowed) "PERMITIR" else "BLOQUEAR"}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(tr(context, "cancel")) }
        },
        confirmButton = {
            TextButton(onClick = { onApply(profile) }) {
                Text(if (english) "Apply PERSONALIZED" else "Aplicar PERSONALIZADO")
            }
        }
    )
}

@Composable
internal fun CustomProtectionChecklist(
    profile: CustomProtectionProfileStore.Profile,
    english: Boolean,
    onProfileChange: (CustomProtectionProfileStore.Profile) -> Unit
) {
    @Composable
    fun row(title: String, subtitle: String, checked: Boolean, set: (Boolean) -> CustomProtectionProfileStore.Profile) {
        Row(
            Modifier.fillMaxWidth().padding(vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(title, style = MaterialTheme.typography.bodyMedium)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Checkbox(checked = checked, onCheckedChange = { onProfileChange(set(it)) })
        }
    }

    row(
        if (english) "Ads and trackers" else "Anuncios y rastreadores",
        if (english) "Block domains from Hydra's ad/tracker list." else "Bloquea dominios de la lista de anuncios/rastreadores de Hydra.",
        profile.adTrackerBlocklist
    ) { profile.copy(adTrackerBlocklist = it) }
    row(
        if (english) "Secure DNS" else "DNS seguro",
        if (english) "Use Hydra's encrypted DNS path for this app." else "Usa el camino de DNS cifrado de Hydra para esta app.",
        profile.secureDns
    ) { profile.copy(secureDns = it) }
    row(
        if (english) "HTTPS SNI filter" else "Filtro SNI HTTPS",
        if (english) "Inspect TLS ClientHello SNI for domain filtering." else "Inspecciona el SNI del ClientHello TLS para filtrar dominios.",
        profile.tlsSniFilter
    ) { profile.copy(tlsSniFilter = it) }
    row(
        if (english) "QUIC protection" else "Protección QUIC",
        if (english) "Inspect HTTP/3/QUIC traffic for domain policy." else "Inspecciona tráfico HTTP/3/QUIC para aplicar la política de dominios.",
        profile.quicProtection
    ) { profile.copy(quicProtection = it) }
    row(
        if (english) "Known-threat protection" else "Protección contra amenazas conocidas",
        if (english) "Block confirmed threat IPs and domains." else "Bloquea IP y dominios de amenazas confirmadas.",
        profile.threatProtection
    ) { profile.copy(threatProtection = it) }
    row(
        if (english) "Block local network" else "Bloquear red local",
        if (english) "Block connections to private/local addresses for this app." else "Bloquea conexiones a direcciones privadas/locales para esta app.",
        profile.blockLocalNetwork
    ) { profile.copy(blockLocalNetwork = it) }
}

internal fun customProtectionSummary(profile: CustomProtectionProfileStore.Profile, english: Boolean): String {
    val enabled = mutableListOf<String>()
    if (profile.adTrackerBlocklist) enabled += if (english) "ads/trackers" else "ads/trackers"
    if (profile.secureDns) enabled += "DNS"
    if (profile.tlsSniFilter) enabled += "SNI"
    if (profile.quicProtection) enabled += "QUIC"
    if (profile.threatProtection) enabled += if (english) "threats" else "amenazas"
    if (profile.blockLocalNetwork) enabled += if (english) "local network block" else "bloqueo red local"
    return if (english) {
        "Active: ${if (enabled.isEmpty()) "none" else enabled.joinToString(", ") }"
    } else {
        "Activas: ${if (enabled.isEmpty()) "ninguna" else enabled.joinToString(", ") }"
    }
}

@Composable
internal fun ProtectionTabContent(
    advancedMode: Boolean,
    onAdvancedModeChange: (Boolean) -> Unit,
    context: Context,
    language: AppLanguage,
    protection: ProtectionStatus.Snapshot,
    isOn: Boolean,
    network: NetworkKind,
    roaming: Boolean,
    globalBlockAll: Boolean,
    threatProtectionEnabled: Boolean,
    blockAdsListInfo: DomainBlockStore.ListInfo,
    blockAdsBlockedToday: Long,
    blockAdsCheckState: BlockAdsCheckState,
    trafficHistory: List<Pair<Float, Float>>,
    connectionHistory: List<com.hydra.firewall.vpn.ConnectionHistory.Record>,
    onToggleVpn: (Boolean) -> Unit,
    onGlobalBlockAllChange: (Boolean) -> Unit,
    onThreatProtectionChange: (Boolean) -> Unit,
    onCheckBlocklist: () -> Unit,
    onUpdateBlocklist: () -> Unit,
    onKillSwitch: () -> Unit,
    onOpenSecurity: () -> Unit = {},
    onOpenConnections: () -> Unit = {}
) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 10.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Spacer(Modifier.height(6.dp))
        HomeStatusRow(language.isEnglish(), isOn, network, roaming, onToggleVpn)
        Spacer(Modifier.height(10.dp))
        var showAssistant by remember { mutableStateOf(false) }
        HomeHealthCard(context, language.isEnglish(), isOn, blockAdsBlockedToday) { showAssistant = true }
        Spacer(Modifier.height(10.dp))
        if (showAssistant) AppNotWorkingAssistant(context, language.isEnglish()) { showAssistant = false }
        if (isOn) {
            HomeAlertsCard(context, language.isEnglish())
            Spacer(Modifier.height(10.dp))
        }
        HomeLiveTrafficCard(language.isEnglish(), trafficHistory, blockAdsBlockedToday)
        Spacer(Modifier.height(10.dp))
        HomeRecentDecisionsCard(language.isEnglish(), connectionHistory, onOpenConnections = onOpenConnections)
        Spacer(Modifier.height(10.dp))
        PauseCard(context, language.isEnglish(), isOn) { onToggleVpn(true) }
        val homeThreats = remember(blockAdsBlockedToday) { com.hydra.firewall.security.AppThreatScanner.findings(context).size }
        val homeLastScan = remember(blockAdsBlockedToday) { com.hydra.firewall.security.AppThreatScanner.lastFullScan(context) }
        if (advancedMode) Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            HomeStatTile(Modifier.weight(1f), blockAdsBlockedToday.toString(), if (language.isEnglish()) "blocked today" else "bloqueos hoy")
            HomeStatTile(Modifier.weight(1f), blockAdsListInfo.domainCount.toString(), if (language.isEnglish()) "domains in list" else "dominios en lista")
            HomeStatTile(Modifier.weight(1f), homeThreats.toString(), if (language.isEnglish()) "threats" else "amenazas")
        }
        Spacer(Modifier.height(10.dp))
        HydraCard(
            Modifier.fillMaxWidth().clickable { onOpenSecurity() },
            shape = RoundedCornerShape(16.dp)
        ) {
            Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(10.dp).clip(CircleShape).background(
                        when {
                            homeThreats > 0 -> Color(0xFFF87171)
                            homeLastScan == 0L -> Color(0xFFFBBF24)
                            else -> Color(0xFF34D399)
                        }
                    )
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    when {
                        homeThreats > 0 -> if (language.isEnglish()) "Security: $homeThreats app(s) need attention" else "Seguridad: $homeThreats app(s) requieren atención"
                        homeLastScan == 0L -> if (language.isEnglish()) "Security: apps not checked yet" else "Seguridad: todavía sin revisar las apps"
                        else -> if (language.isEnglish()) "Security: protected" else "Seguridad: protegido"
                    },
                    fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f)
                )
                Text(if (language.isEnglish()) "View" else "Ver", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
            }
        }
        Spacer(Modifier.height(8.dp))
        // Weekly summary (the Normal/Advanced switch lives only in Settings).
        WeeklySummaryCard(context, language.isEnglish())
        Spacer(Modifier.height(4.dp))
        if (advancedMode || globalBlockAll) SettingSwitchCard(
            if (language.isEnglish()) "Block all traffic" else "Bloquear todo el tráfico",
            if (language.isEnglish())
                "Stops normal traffic decisions globally while enabled."
            else
                "Detiene globalmente las decisiones normales de tráfico mientras está activo.",
            globalBlockAll,
            onGlobalBlockAllChange
        )

        Spacer(Modifier.height(4.dp))
        SettingSwitchCard(
            if (language.isEnglish()) "Threats + ads" else "Amenazas + publicidad",
            if (language.isEnglish())
                "Blocks known ad/tracker domains and known threat domains/IPs. Lists update automatically in the background and new data applies to future DNS/SNI checks without restarting the VPN. Secure DNS remains configurable in Settings."
            else
                "Bloquea dominios conocidos de anuncios/rastreadores y dominios/IP de amenazas. Las listas se actualizan solas y se aplican a las próximas consultas DNS/SNI sin reiniciar la VPN. El DNS seguro sigue siendo configurable en Ajustes.",
            threatProtectionEnabled,
            onThreatProtectionChange
        )

        if (threatProtectionEnabled) {
            BlockAdsSection(
                context = context,
                listInfo = blockAdsListInfo,
                blockedToday = blockAdsBlockedToday,
                checkState = blockAdsCheckState,
                onCheckForUpdate = onCheckBlocklist,
                onUpdateNow = onUpdateBlocklist
            )
        }

        var showDiag by remember { mutableStateOf(false) }
        Spacer(Modifier.height(10.dp))
        if (advancedMode) HydraCard(Modifier.fillMaxWidth().clickable { showDiag = !showDiag }, shape = RoundedCornerShape(16.dp)) {
            Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(if (language.isEnglish()) "System details" else "Detalles del sistema", fontWeight = FontWeight.SemiBold)
                    Text(
                        if (language.isEnglish()) "Kill switch, DNS, blocklist and integrity status" else "Kill switch, DNS, lista e integridad",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(if (showDiag) "▲" else "▼", color = MaterialTheme.colorScheme.primary)
            }
        }
        if (showDiag) {
        Spacer(Modifier.height(10.dp)); HorizontalDivider(); Spacer(Modifier.height(10.dp))
        Text(if (language.isEnglish()) "System kill switch" else "Kill switch del sistema", style = MaterialTheme.typography.titleMedium)
        Text(
            if (language.isEnglish())
                "This is controlled by Android VPN settings. Hydra cannot manufacture a stronger system lockdown when Android or the device firmware does not expose it."
            else
                "Esto lo controla la configuración VPN de Android. Hydra no puede crear un bloqueo del sistema más fuerte cuando Android o el firmware del equipo no lo ofrecen.",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(5.dp))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Text(
                if (FirewallVpnService.alwaysOnEnabled)
                    (if (language.isEnglish()) "Always-on VPN: ✓ enabled" else "VPN siempre activa: ✓ activada")
                else
                    (if (language.isEnglish()) "Always-on VPN: ✗ not enabled" else "VPN siempre activa: ✗ no activada"),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                if (FirewallVpnService.lockdownEnabled)
                    (if (language.isEnglish()) "Block connections without VPN: ✓ enabled" else "Bloquear conexiones sin VPN: ✓ activado")
                else
                    (if (language.isEnglish()) "Block connections without VPN: ✗ not enabled (check Android VPN settings)" else "Bloquear conexiones sin VPN: ✗ no activado (revisá Ajustes VPN de Android)"),
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            Text(
                if (language.isEnglish())
                    "Always-on VPN: Android setting available; lockdown is not exposed to a normal VPN app on this Android generation."
                else
                    "VPN siempre activa: Android ofrece el ajuste; el bloqueo sin VPN (Lockdown) no está expuesto a una app VPN normal en esta generación de Android.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (language.isEnglish())
                    "Hydra will not claim a system kill switch that the OS cannot provide."
                else
                    "Hydra no va a marcar como activo un kill switch del sistema que el sistema operativo no puede proporcionar.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(4.dp))
        Button(onClick = onKillSwitch) {
            Text(if (language.isEnglish()) "OPEN VPN SETTINGS" else "ABRIR AJUSTES VPN")
        }

        }
        Spacer(Modifier.height(6.dp))

        if (showDiag) {
        Spacer(Modifier.height(10.dp)); HorizontalDivider(); Spacer(Modifier.height(10.dp))
        Text(if (language.isEnglish()) "Current protection status" else "Estado actual de protección", style = MaterialTheme.typography.titleMedium)
        Text(
            when (protection.level) {
                ProtectionStatus.Level.ACTIVE -> if (language.isEnglish()) "● PROTECTION ACTIVE" else "● PROTECCIÓN ACTIVA"
                ProtectionStatus.Level.PARTIAL -> if (language.isEnglish()) "● PROTECTION PARTIAL" else "● PROTECCIÓN PARCIAL"
                ProtectionStatus.Level.OFF -> if (language.isEnglish()) "○ PROTECTION OFF" else "○ PROTECCIÓN DESACTIVADA"
            },
            fontWeight = FontWeight.Bold,
            color = when (protection.level) {
                ProtectionStatus.Level.ACTIVE -> Color(0xFF2E8B57)
                ProtectionStatus.Level.PARTIAL -> Color(0xFFD98E1F)
                ProtectionStatus.Level.OFF -> MaterialTheme.colorScheme.error
            }
        )
        Spacer(Modifier.height(3.dp))
        Text(
            if (language.isEnglish())
                "VPN: ${if (protection.vpn) "✓ active" else "✗ stopped"}"
            else
                "VPN: ${if (protection.vpn) "✓ activa" else "✗ detenida"}",
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            if (language.isEnglish()) {
                "Secure DNS: ${when { !protection.secureDnsEnabled -> "off (optional)"; protection.dns -> "✓ ready"; else -> "✗ requires VPN" }}"
            } else {
                "DNS seguro: ${when { !protection.secureDnsEnabled -> "desactivado (opcional)"; protection.dns -> "✓ listo"; else -> "✗ requiere VPN" }}"
            },
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            if (language.isEnglish()) {
                if (protection.blocklistEnabled)
                    "Blocklist: ${if (protection.blocklist) "✓ applied" else "✗ not applied"} • ${protection.blocklistCount} domains • ${protection.blocklistSource}"
                else
                    "Blocklist: off (optional)"
            } else {
                if (protection.blocklistEnabled)
                    "Lista: ${if (protection.blocklist) "✓ aplicada" else "✗ no aplicada"} • ${protection.blocklistCount} dominios • ${protection.blocklistSource}"
                else
                    "Lista: desactivada (opcional)"
            },
            style = MaterialTheme.typography.bodySmall
        )

        val integrityResult = AppIntegrity.inspect(context)
        Text(
            if (language.isEnglish()) {
                "App integrity: ${when (integrityResult.detail) {
                    "debuggable_build" -> "debug build (informational only)"
                    "signer_unavailable" -> "signer unavailable"
                    else -> "release signature present"
                }}"
            } else {
                "Integridad de la app: ${when (integrityResult.detail) {
                    "debuggable_build" -> "compilación DEBUG (solo informativo)"
                    "signer_unavailable" -> "firma no disponible"
                    else -> "firma de versión release presente"
                }}"
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (protection.missing.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text(
                if (language.isEnglish())
                    "Still missing: ${protection.missing.joinToString(" • ") }"
                else
                    "Todavía falta: ${protection.missing.joinToString(" • ") }",
                style = MaterialTheme.typography.bodySmall,
                color = if (protection.level == ProtectionStatus.Level.OFF) MaterialTheme.colorScheme.error else Color(0xFFD98E1F)
            )
        } else {
            Text(
                if (language.isEnglish()) "All essential prerequisites are satisfied." else "Todos los requisitos esenciales están satisfechos.",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF2E8B57)
            )
        }
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
internal fun DnsProviderSection(
    context: android.content.Context,
    english: Boolean,
    transport: com.hydra.firewall.vpn.DnsTransport,
    onTransportChange: (com.hydra.firewall.vpn.DnsTransport) -> Unit,
    provider: com.hydra.firewall.vpn.DnsProvider,
    customIpv4: String,
    customIpv6: String,
    customHostname: String,
    customDohUrl: String,
    onProviderChange: (com.hydra.firewall.vpn.DnsProvider) -> Unit,
    onCustomIpv4Change: (String) -> Unit,
    onCustomIpv6Change: (String) -> Unit,
    onCustomHostnameChange: (String) -> Unit,
    onCustomDohUrlChange: (String) -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(top = 6.dp)) {
        Text(if (english) "Encrypted transport" else "Transporte cifrado", style = MaterialTheme.typography.bodyMedium)
        Text(
            if (english) "DoT works over TLS/853; DoH works over HTTPS and is useful when UDP/53 is restricted."
            else "DoT usa TLS/853; DoH usa HTTPS y es útil cuando UDP/53 está restringido.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        DnsProviderOptionRow(
            context = context,
            selected = transport == com.hydra.firewall.vpn.DnsTransport.DOT,
            title = "DoT (TLS)",
            subtitle = if (english) "Default encrypted DNS transport" else "Transporte DNS cifrado predeterminado",
            isDefault = transport == com.hydra.firewall.vpn.DnsTransport.DOT,
            onClick = { onTransportChange(com.hydra.firewall.vpn.DnsTransport.DOT) }
        )
        DnsProviderOptionRow(
            context = context,
            selected = transport == com.hydra.firewall.vpn.DnsTransport.DOH,
            title = "DoH (HTTPS)",
            subtitle = if (english) "Encrypted DNS over HTTPS" else "DNS cifrado sobre HTTPS",
            onClick = { onTransportChange(com.hydra.firewall.vpn.DnsTransport.DOH) }
        )
        Spacer(Modifier.height(8.dp))
        Text(tr(context, "dns_provider"), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(6.dp))

        DnsProviderOptionRow(
            context = context,
            selected = provider == com.hydra.firewall.vpn.DnsProvider.CLOUDFLARE,
            title = "Cloudflare",
            subtitle = tr(context, "dns_provider_cloudflare_sub"),
            isDefault = true,
            onClick = { onProviderChange(com.hydra.firewall.vpn.DnsProvider.CLOUDFLARE) }
        )
        DnsProviderOptionRow(
            context = context,
            selected = provider == com.hydra.firewall.vpn.DnsProvider.GOOGLE,
            title = "Google",
            subtitle = tr(context, "dns_provider_google_sub"),
            onClick = { onProviderChange(com.hydra.firewall.vpn.DnsProvider.GOOGLE) }
        )
        DnsProviderOptionRow(
            context = context,
            selected = provider == com.hydra.firewall.vpn.DnsProvider.QUAD9,
            title = "Quad9",
            subtitle = tr(context, "dns_provider_quad9_sub"),
            onClick = { onProviderChange(com.hydra.firewall.vpn.DnsProvider.QUAD9) }
        )
        DnsProviderOptionRow(
            context = context,
            selected = provider == com.hydra.firewall.vpn.DnsProvider.CUSTOM,
            title = tr(context, "dns_provider_custom"),
            subtitle = tr(context, "dns_provider_custom_sub"),
            onClick = { onProviderChange(com.hydra.firewall.vpn.DnsProvider.CUSTOM) }
        )

        if (provider == com.hydra.firewall.vpn.DnsProvider.CUSTOM) {
            Column(Modifier.fillMaxWidth().padding(start = 8.dp, top = 4.dp, bottom = 4.dp)) {
                OutlinedTextField(
                    customIpv4, onCustomIpv4Change, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(tr(context, "dns_custom_ipv4")) }
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    customIpv6, onCustomIpv6Change, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(tr(context, "dns_custom_ipv6")) }
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    customHostname, onCustomHostnameChange, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(tr(context, "dns_custom_hostname")) }
                )
                if (transport == com.hydra.firewall.vpn.DnsTransport.DOH) {
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        customDohUrl, onCustomDohUrlChange, Modifier.fillMaxWidth(), singleLine = true,
                        label = { Text(if (english) "Custom DoH URL" else "URL DoH personalizada") },
                        supportingText = { Text(if (english) "Must start with https://" else "Debe comenzar con https://") }
                    )
                }
                if ((customIpv4.isBlank() && customIpv6.isBlank()) || customHostname.isBlank() ||
                    (transport == com.hydra.firewall.vpn.DnsTransport.DOH && !customDohUrl.startsWith("https://", ignoreCase = true))) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        tr(context, "dns_custom_incomplete"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
internal fun DnsProviderOptionRow(
    context: android.content.Context,
    selected: Boolean,
    title: String,
    subtitle: String,
    isDefault: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(Modifier.width(4.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.bodyMedium)
                if (isDefault) {
                    Spacer(Modifier.width(6.dp))
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(5.dp))
                            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f))
                            .padding(horizontal = 6.dp, vertical = 1.dp)
                    ) {
                        Text(
                            tr(context, "dns_provider_default_badge"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
            Text(subtitle, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun BlockAdsSection(
    context: android.content.Context,
    listInfo: DomainBlockStore.ListInfo,
    blockedToday: Long,
    checkState: BlockAdsCheckState,
    onCheckForUpdate: () -> Unit,
    onUpdateNow: () -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(top = 6.dp)) {
        val dateLabel = listInfo.date.ifBlank { "—" }
        Text(
            String.format(tr(context, "block_ads_list_status"), dateLabel, listInfo.domainCount.toString()),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            String.format(tr(context, "block_ads_blocked_today"), blockedToday.toString()),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            if (AppSettings(context).language.isEnglish())
                "Automatic background updates (about every 24 hours, on unmetered networks). New lists are applied live; you do not need to turn the VPN off and on. Apps may keep cached DNS or existing connections until they reconnect."
            else
                "Actualización automática en segundo plano (aprox. cada 24 horas, con redes no medidas). Las listas nuevas se aplican en vivo: no hace falta apagar y encender la VPN. Las apps pueden conservar DNS en caché o conexiones existentes hasta reconectarse.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))

        when (checkState) {
            is BlockAdsCheckState.Checking -> {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(tr(context, "block_ads_checking"), style = MaterialTheme.typography.bodySmall)
                }
            }
            is BlockAdsCheckState.Updating -> {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(tr(context, "block_ads_updating"), style = MaterialTheme.typography.bodySmall)
                }
            }
            is BlockAdsCheckState.NewAvailable -> {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f))
                        .padding(10.dp)
                ) {
                    Text(
                        String.format(tr(context, "block_ads_new_available"), checkState.remoteDate),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(6.dp))
                    Button(onClick = onUpdateNow) { Text(tr(context, "block_ads_update_now")) }
                }
            }
            else -> {
                OutlinedButton(onClick = onCheckForUpdate) { Text(tr(context, "block_ads_check_update")) }
                when (checkState) {
                    is BlockAdsCheckState.CheckFailed -> Column(Modifier.padding(top = 4.dp)) {
                        Text(tr(context, "block_ads_check_failed"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                        checkState.error?.takeIf { it.isNotBlank() }?.let { err ->
                            val friendly = if (err.contains("Trust anchor", true) || err.contains("CertPathValidator", true) || err.contains("SSLHandshakeException", true)) {
                                "El dispositivo rechazó el certificado HTTPS de la fuente. Hydra conserva la lista anterior; intentá nuevamente."
                            } else err
                            Text("Error: $friendly", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
                        }
                    }
                    is BlockAdsCheckState.UpToDate -> Text(
                        tr(context, "block_ads_up_to_date"),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    is BlockAdsCheckState.UpdateSuccess -> Text(
                        String.format(tr(context, "block_ads_update_success"), checkState.domainCount.toString()),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    is BlockAdsCheckState.UpdateSkipped -> Text(
                        "Lista ya actualizada: ${checkState.domainCount} dominios • ${checkState.remoteDate}",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    is BlockAdsCheckState.UpdateFailed -> Column(Modifier.padding(top = 4.dp)) {
                        Text(tr(context, "block_ads_update_failed"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                        checkState.error?.takeIf { it.isNotBlank() }?.let { Text("Error: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error) }
                    }
                    else -> Unit
                }
            }
        }
    }
}
