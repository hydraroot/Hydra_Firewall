package com.hydra.firewall

import android.content.Context
import android.net.Uri
import android.widget.ImageView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationManagerCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.vpn.*
import com.hydra.firewall.security.*
import java.util.Locale

/**
 * "Security Center" tab: surfaces the six FIX70 features in one place so
 * none of them need to be hunted for across the app. Everything here reads
 * from stores that the VPN engines already write to on the hot path; this
 * screen never touches the network itself, only SharedPreferences/in-memory
 * snapshots, so it's safe to leave open while the firewall runs.
 */
@Composable
fun SecurityCenterTab(context: Context, language: AppLanguage) {
    val english = language.isEnglish() ||
        (language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
    var refreshTrigger by remember { mutableStateOf(0) }
    val ipBlockStore = remember { IpBlockStore(context) }
    val advancedRuleStore = remember { AdvancedRuleStore(context) }
    val quarantineManager = remember { QuarantineManager(context) }

    var section by remember { mutableStateOf(SecuritySection.STATUS) }

    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 10.dp, vertical = 6.dp)) {
        item {
            Text(
                if (english) "Security Center" else "Centro de Seguridad",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (english) "APK scanner, behavior correlation, TLS fingerprinting, update watch, quarantine, Doze correlation, unexpected-stop log and rule cleanup."
                else "Analizador APK, correlación de comportamiento, huella TLS, vigilancia de updates, cuarentena, correlación con Doze, log de paradas inesperadas del servicio y limpieza de reglas.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            SecuritySectionPicker(section, english) { section = it; refreshTrigger++ }
            Spacer(Modifier.height(8.dp))
        }

        when (section) {
            SecuritySection.STATUS -> statusSection(this, context, english, quarantineManager, refreshTrigger)
            SecuritySection.APK_SCANNER -> apkScannerSection(this, context, english, refreshTrigger)
            SecuritySection.BEHAVIOR -> behaviorSection(this, context, english, refreshTrigger)
            SecuritySection.FINGERPRINT -> fingerprintSection(this, context, english, refreshTrigger) { refreshTrigger++ }
            SecuritySection.QUARANTINE -> quarantineSection(this, context, english, quarantineManager, refreshTrigger) { refreshTrigger++ }
            SecuritySection.UPDATE_WATCH -> updateWatchSection(this, context, english, refreshTrigger) { refreshTrigger++ }
            SecuritySection.DOZE -> dozeSection(this, english, refreshTrigger)
            SecuritySection.TAMPER -> tamperSection(this, english, refreshTrigger) { refreshTrigger++ }
            SecuritySection.CONFLICTS -> conflictsSection(this, english, ipBlockStore, advancedRuleStore, refreshTrigger) { refreshTrigger++ }
            SecuritySection.TIMELINE -> timelineSection(this, context, english, refreshTrigger)
        }

        item { Spacer(Modifier.height(24.dp)) }
    }
}

private enum class SecuritySection { STATUS, APK_SCANNER, BEHAVIOR, FINGERPRINT, QUARANTINE, UPDATE_WATCH, DOZE, TAMPER, CONFLICTS, TIMELINE }

@Composable
private fun SecuritySectionPicker(current: SecuritySection, english: Boolean, onPick: (SecuritySection) -> Unit) {
    val labels = mapOf(
        SecuritySection.STATUS to (if (english) "Protection" else "Protección"),
        SecuritySection.APK_SCANNER to (if (english) "APK scanner" else "Analizar APK"),
        SecuritySection.BEHAVIOR to (if (english) "Behavior" else "Comportamiento"),
        SecuritySection.FINGERPRINT to (if (english) "TLS fingerprint" else "Huella TLS"),
        SecuritySection.QUARANTINE to (if (english) "Quarantine" else "Cuarentena"),
        SecuritySection.UPDATE_WATCH to (if (english) "Update watch" else "Vigilar updates"),
        SecuritySection.DOZE to "Doze",
        SecuritySection.TAMPER to (if (english) "Unexpected stops" else "Parada inesperada"),
        SecuritySection.CONFLICTS to (if (english) "Rule cleanup" else "Reglas"),
        SecuritySection.TIMELINE to (if (english) "Timeline" else "Línea de tiempo")
    )
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
        labels.forEach { (section, label) ->
            val selected = section == current
            AssistChip(
                onClick = { onPick(section) },
                label = { Text(label, fontSize = 11.sp) },
                colors = AssistChipDefaults.assistChipColors(
                    containerColor = if (selected) Color(0xFFE3D0FF) else MaterialTheme.colorScheme.surfaceVariant,
                    labelColor = if (selected) Color(0xFF241A34) else MaterialTheme.colorScheme.onSurfaceVariant
                ),
                modifier = Modifier.padding(end = 6.dp)
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 0) Protection status / integrity overview
// ---------------------------------------------------------------------------
private fun statusSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    quarantineManager: QuarantineManager,
    refreshTrigger: Int
) = with(scope) {
    item {
        val protection = ProtectionStatus.read(context)
        val ruleStore = remember { RuleStore(context) }
        val listInfo = DomainBlockStore.activeListInfo()
        val threat = ThreatSignatureStore.status(context)
        val threatIntel = ThreatIntelDomainStore.info(context)
        val customRules = CustomDomainRuleStore.snapshot(context)
        val tlsEnabled = TlsFingerprintStore.isEnabled()
        val tlsBlock = TlsFingerprintStore.isBlockOnMatchEnabled()
        val securityAi = runCatching { HydraAiEngine.init(context); HydraAiEngine.isLoaded() }.getOrDefault(false)
        val privacyAi = runCatching { HydraPrivacyAiEngine.init(context); HydraPrivacyAiEngine.isLoaded() }.getOrDefault(false)
        val mh100kAi = runCatching { HydraMh100kApkAi.init(context); HydraMh100kApkAi.isLoaded() }.getOrDefault(false)
        val integrity = AppIntegrity.inspect(context)
        val notificationsEnabled = NotificationManagerCompat.from(context).areNotificationsEnabled()
        val adaptiveApps = AppBehaviorBaselineStore.trainedApps(context)
        val directBootPending = DirectBootState.pending(context)
        val lastConn = ConnectionHistory.snapshot().firstOrNull()
        val secondsSincePacket = if (FirewallVpnService.lastPacketAt > 0)
            (System.currentTimeMillis() - FirewallVpnService.lastPacketAt) / 1000 else -1L

        Text(
            if (english) "Protection overview" else "Resumen de protección",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
        Text(
            if (english) "Here you can see what is protecting the device now, what is optional/off, and what Android itself limits."
            else "Acá ves qué está protegiendo el equipo ahora, qué es opcional o está desactivado y qué limita el propio Android.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))

        SmallCard {
            Text(if (english) "PROTECTION NOW" else "PROTECCIÓN AHORA", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(
                when (protection.level) {
                    ProtectionStatus.Level.ACTIVE -> if (english) "● ACTIVE" else "● ACTIVA"
                    ProtectionStatus.Level.PARTIAL -> if (english) "● PARTIAL" else "● PARCIAL"
                    ProtectionStatus.Level.OFF -> if (english) "○ OFF" else "○ DESACTIVADA"
                },
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = when (protection.level) {
                    ProtectionStatus.Level.ACTIVE -> Color(0xFF2E8B57)
                    ProtectionStatus.Level.PARTIAL -> Color(0xFFD98E1F)
                    ProtectionStatus.Level.OFF -> MaterialTheme.colorScheme.error
                }
            )
            if (protection.missing.isNotEmpty()) {
                Text(
                    if (english) "Missing: ${protection.missing.joinToString(" • ")}" else "Falta: ${protection.missing.joinToString(" • ")}",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.error
                )
            } else {
                Text(
                    if (english) "All required core conditions are satisfied." else "Todas las condiciones esenciales están satisfechas.",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        Text(if (english) "ACTIVE PROTECTIONS" else "PROTECCIONES ACTIVAS", fontSize = 13.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))

        StatusRow(english, protection.vpn, "VPN / túnel TUN", "VPN / TUN tunnel")
        StatusRow(english, protection.vpn, "Firewall TCP + UDP", "TCP + UDP firewall")
        StatusRow(english, protection.vpn, "IPv4 + IPv6 Internet", "IPv4 + IPv6 Internet")
        StatusRow(
            english,
            protection.blocklistEnabled && protection.blocklist,
            "Blocklist aplicada (${protection.blocklistCount})",
            "Blocklist applied (${protection.blocklistCount})"
        )
        StatusRow(
            english,
            threatIntel.count > 0,
            "Inteligencia de amenazas (${threatIntel.count} dominios)",
            "Threat intelligence (${threatIntel.count} domains)"
        )
        StatusRow(
            english,
            threat.enabled && (threat.sha256Count + threat.domainCount + threat.ipCount + threat.urlCount + threat.yaraRuleCount > 0),
            "Firmas de amenazas (${threat.packVersion})",
            "Threat signatures (${threat.packVersion})"
        )
        StatusRow(english, protection.vpn, "Bloqueo HTTPS/SNI", "HTTPS/SNI blocking")
        StatusRow(english, protection.vpn, "Protección QUIC por correlación DNS→IP", "QUIC protection via DNS→IP correlation")
        StatusRow(english, securityAi, "IA de seguridad de comportamiento", "Behavior security AI")
        StatusRow(english, privacyAi, "IA de privacidad local", "Local privacy AI")
        StatusRow(english, mh100kAi, "IA estática de APK (MH-100K)", "APK static AI (MH-100K)")
        StatusRow(english, notificationsEnabled, "Avisos de amenazas graves disponibles", "High/critical threat alerts available")
        StatusRow(english, true, "Recuperación del servicio VPN", "VPN service recovery")
        StatusRow(english, !directBootPending, if (directBootPending) "Recuperación post-reinicio pendiente" else "Recuperación post-reinicio lista", if (directBootPending) "Post-reboot recovery pending" else "Post-reboot recovery ready")
        StatusRow(english, adaptiveApps > 0, "Aprendizaje local de comportamiento (${adaptiveApps} apps)", "Local behavior learning (${adaptiveApps} apps)")
        if (ruleStore.threatProtectionEnabled) StatusRow(english, true, "Amenazas + publicidad", "Threats + ads")
        if (ruleStore.secureDnsEnabled) StatusRow(english, protection.dns, "DNS seguro (${ruleStore.dnsTransport.name})", "Secure DNS (${ruleStore.dnsTransport.name})")
        if (tlsEnabled) StatusRow(english, true, "Huella TLS / JA3", "TLS / JA3 fingerprinting")
        if (tlsEnabled && tlsBlock) StatusRow(english, true, "Cortar por huella TLS conocida", "Reset on known-bad TLS fingerprint")
        if (quarantineManager.enabled) StatusRow(english, true, "Cuarentena de apps nuevas", "New-app quarantine")
        if (ruleStore.globalBlockAll) StatusRow(english, true, "Bloquear todo el tráfico", "Block all traffic")
        if (customRules.isNotEmpty()) StatusRow(english, true, "Reglas de dominio personalizadas (${customRules.size})", "Custom domain rules (${customRules.size})")

        Spacer(Modifier.height(10.dp))
        Text(if (english) "OPTIONAL / CURRENTLY OFF" else "OPCIONAL / ACTUALMENTE DESACTIVADO", fontSize = 13.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        if (!ruleStore.threatProtectionEnabled) OptionalStatusRow(english, false, "Amenazas + publicidad", "Threats + ads")
        if (!ruleStore.secureDnsEnabled) OptionalStatusRow(english, false, "DNS seguro", "Secure DNS")
        if (!tlsEnabled) OptionalStatusRow(english, false, "Huella TLS / JA3", "TLS / JA3 fingerprinting")
        if (!tlsEnabled || !tlsBlock) OptionalStatusRow(english, false, "Cortar por huella TLS conocida", "Reset on known-bad TLS fingerprint")
        if (!quarantineManager.enabled) OptionalStatusRow(english, false, "Cuarentena de apps nuevas", "New-app quarantine")
        if (!ruleStore.globalBlockAll) OptionalStatusRow(english, false, "Bloquear todo el tráfico", "Block all traffic")
        if (customRules.isEmpty()) OptionalStatusRow(english, false, "Reglas de dominio personalizadas", "Custom domain rules")
        OptionalStatusRow(english, ruleStore.learningMode, "Modo aprendizaje", "Learning mode")

        Spacer(Modifier.height(10.dp))
        Text(if (english) "SYSTEM / DEVICE LIMITATIONS" else "LIMITACIONES DEL SISTEMA / EQUIPO", fontSize = 13.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        StatusCaveat(english, "Kill switch Lockdown: ${if (android.os.Build.VERSION.SDK_INT >= 29) if (FirewallVpnService.lockdownEnabled) "ACTIVO" else "no activado" else "no disponible en esta generación de Android"}", "Kill switch Lockdown: ${if (android.os.Build.VERSION.SDK_INT >= 29) if (FirewallVpnService.lockdownEnabled) "ACTIVE" else "not enabled" else "not available on this Android generation"}")
        StatusCaveat(english, "IPv6 local (fe80::/10 y ff00::/8) queda fuera del túnel para conservar descubrimiento local de Android.", "Local IPv6 (fe80::/10 and ff00::/8) stays outside the tunnel to preserve Android local discovery.")
        StatusCaveat(english, "Hydra queda excluida de su propio túnel para evitar un bucle de tráfico.", "Hydra is excluded from its own tunnel to avoid traffic looping.")
        StatusCaveat(english, "Si una app usa su propio DoH, Hydra puede filtrar por app/IP/puerto/fingerprint, pero no siempre puede ver el dominio consultado dentro de ese DoH.", "If an app uses its own DoH, Hydra can filter by app/IP/port/fingerprint, but may not see the queried domain inside that DoH connection.")

        Spacer(Modifier.height(10.dp))
        SmallCard {
            Text(if (english) "CURRENT HEALTH" else "SALUD ACTUAL", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(
                when {
                    !protection.vpn -> if (english) "VPN is off" else "VPN apagada"
                    secondsSincePacket < 0 -> if (english) "VPN active • no packets observed yet" else "VPN activa • todavía no se observaron paquetes"
                    secondsSincePacket < 60 -> if (english) "Last packet: ${secondsSincePacket}s ago" else "Último paquete: hace ${secondsSincePacket}s"
                    else -> if (english) "Last packet: ${secondsSincePacket / 60}m ago" else "Último paquete: hace ${secondsSincePacket / 60}m"
                },
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (english) "Blocklist: ${listInfo.domainCount} domains • ${listInfo.source}" else "Lista: ${listInfo.domainCount} dominios • ${listInfo.source}",
                fontSize = 11.sp
            )
            Text(
                if (english) "Threat blocks today: ${ThreatSignatureStore.blockedToday(context)} • Ad/tracker blocks today: ${DomainBlockStore.blockedToday()}"
                else "Amenazas bloqueadas hoy: ${ThreatSignatureStore.blockedToday(context)} • Ads/trackers bloqueados hoy: ${DomainBlockStore.blockedToday()}",
                fontSize = 11.sp
            )
            Text(
                if (english) "App integrity: ${if (integrity.detail == "debuggable_build") "DEBUG build (informational)" else "release signature present"}"
                else "Integridad: ${if (integrity.detail == "debuggable_build") "compilación DEBUG (informativo)" else "firma release presente"}",
                fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        SmallCard {
            ThreatPackCard(english, refreshTrigger)
        }

        SmallCard {
            Text(if (english) "LAST SECURITY DECISION" else "ÚLTIMA DECISIÓN DE SEGURIDAD", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(
                if (lastConn == null) (if (english) "No connection decisions recorded yet" else "Todavía no hay decisiones de conexión registradas")
                else "${if (lastConn.allowed) "✅ ALLOW" else "⛔ BLOCK"} — ${lastConn.packageName ?: "uid:${lastConn.uid}"} → ${lastConn.destination} (${lastConn.time})",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun OptionalStatusRow(english: Boolean, active: Boolean, esLabel: String, enLabel: String) {
    val color = if (active) Color(0xFF2E8B57) else Color(0xFF8A8790)
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(if (active) "✓" else "○", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = color)
        Spacer(Modifier.width(8.dp))
        Text(if (english) enLabel else esLabel, fontSize = 12.sp, color = color)
    }
}

@Composable
private fun StatusCaveat(english: Boolean, esLabel: String, enLabel: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.Top) {
        Text("•", fontSize = 13.sp, color = Color(0xFFD98E1F))
        Spacer(Modifier.width(8.dp))
        Text(if (english) enLabel else esLabel, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun StatusRow(english: Boolean, ok: Boolean, esLabel: String, enLabel: String, invertGoodColor: Boolean = false) {
    val dotColor = if (invertGoodColor) {
        if (ok) Color(0xFFC0392B) else Color(0xFF2E8B57)
    } else {
        if (ok) Color(0xFF2E8B57) else Color(0xFFB0AEB4)
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(9.dp).clip(RoundedCornerShape(50)).background(dotColor))
        Spacer(Modifier.width(8.dp))
        Text(if (english) enLabel else esLabel, fontSize = 13.sp)
    }
}

/** A permanent architectural caveat, not a live on/off toggle: always shown in amber
 *  so it doesn't read as either "broken" (red) or "protected" (green). */
@Composable
private fun CaveatRow(english: Boolean, esLabel: String, enLabel: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.Top) {
        Box(Modifier.padding(top = 3.dp).size(9.dp).clip(RoundedCornerShape(50)).background(Color(0xFFD98E1F)))
        Spacer(Modifier.width(8.dp))
        Text(if (english) enLabel else esLabel, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ---------------------------------------------------------------------------
// 1) JA3/JA3N/Hydra-lite TLS fingerprinting
// ---------------------------------------------------------------------------
private fun fingerprintSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    item {
        var enabled by remember { mutableStateOf(TlsFingerprintStore.isEnabled()) }
        var blockOnMatch by remember { mutableStateOf(TlsFingerprintStore.isBlockOnMatchEnabled()) }
        var newHash by remember { mutableStateOf("") }

        SectionCard {
            RowSwitch(
                if (english) "Fingerprint TLS handshakes (JA3 / JA3N / HYDRA-lite)" else "Analizar handshakes TLS (JA3 / JA3N / HYDRA-lite)",
                enabled
            ) { enabled = it; TlsFingerprintStore.setEnabled(it) }
            Text(
                if (english) "Identifies the TLS client stack behind a connection independent of domain/IP, so known malicious or tracking fingerprints can still be recognized even if the domain changes or hides behind a CDN. A fingerprint match is a lead to review, not proof by itself: the same JA3 can also come from Chrome, a WebView, or any other app using the same legitimate library."
                else "Identifica el stack TLS detrás de una conexión sin depender del dominio/IP, así se pueden reconocer huellas maliciosas o de tracking conocidas aunque cambien de dominio o se escondan detrás de un CDN. Una coincidencia es una pista para revisar, no una prueba por sí sola: el mismo JA3 también puede venir de Chrome, un WebView, o cualquier otra app que use la misma librería legítima.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(6.dp))
            RowSwitch(
                if (english) "Reset connection on known-bad match" else "Cortar conexión si coincide con hash conocido"
                , blockOnMatch
            ) { blockOnMatch = it; TlsFingerprintStore.setBlockOnMatch(it) }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = newHash, onValueChange = { newHash = it },
                    label = { Text(if (english) "Add known-bad JA3 hash" else "Agregar hash JA3 conocido") },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(6.dp))
                Button(onClick = {
                    if (newHash.isNotBlank()) { TlsFingerprintStore.addKnownBad(newHash.trim()); newHash = ""; onChanged() }
                }) { Text(if (english) "Add" else "Agregar") }
            }
        }
    }

    val alerts = TlsFingerprintStore.alerts()
    if (alerts.isNotEmpty()) {
        item {
            Spacer(Modifier.height(8.dp))
            Text(if (english) "Matches against your known-bad list" else "Coincidencias con tu lista de hashes conocidos", style = MaterialTheme.typography.titleSmall)
        }
        items(alerts.take(50)) { s ->
            SmallCard(background = Color(0xFFF1D0D0)) {
                Text("${s.packageName ?: "uid:${s.uid}"} → ${s.sni ?: s.destination}:${s.port}", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Text("JA3 ${s.ja3Hash}", fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                Text(s.time, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    item {
        Spacer(Modifier.height(8.dp))
        Text(if (english) "Recent handshakes" else "Handshakes recientes", style = MaterialTheme.typography.titleSmall)
    }
    val recent = TlsFingerprintStore.snapshot().take(60)
    if (recent.isEmpty()) {
        item { Text(if (english) "Nothing captured yet." else "Todavía no se capturó nada.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(recent) { s ->
            SmallCard {
                Text("${s.packageName ?: "uid:${s.uid}"} → ${s.sni ?: s.destination}:${s.port}", fontSize = 12.sp)
                Text("JA3 ${s.ja3Hash.take(12)}… • JA3N ${s.ja3nHash.take(12)}…", fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2) New-install quarantine
// ---------------------------------------------------------------------------
private fun quarantineSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    manager: QuarantineManager,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    item {
        var enabled by remember { mutableStateOf(manager.enabled) }
        SectionCard {
            RowSwitch(if (english) "Quarantine newly installed apps" else "Poner en cuarentena apps recién instaladas", enabled) {
                enabled = it
                manager.enabled = it
                if (it) manager.syncOnStartup(context)
            }
            Text(
                if (english) "A brand-new app starts blocked on Wi-Fi and mobile until you review it here. Apps already on the phone are never affected."
                else "Una app recién instalada arranca bloqueada en Wi-Fi y datos hasta que la revisés acá. Las apps que ya estaban en el teléfono nunca se ven afectadas.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
    val pending = manager.pendingEntries()
    item {
        Spacer(Modifier.height(8.dp))
        Text(
            if (english) "Pending review (${pending.size})" else "Pendientes de revisión (${pending.size})",
            style = MaterialTheme.typography.titleSmall
        )
    }
    if (pending.isEmpty()) {
        item { Text(if (english) "Nothing pending." else "Nada pendiente.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(pending) { entry ->
            val permissionGroups = remember(entry.packageName) { loadAppPermissionGroups(context, entry.packageName, maxGroups = 8, maxPermissionsPerGroup = 8) }
            SmallCard {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    AndroidView(
                        modifier = Modifier.width(42.dp).height(42.dp),
                        factory = { ImageView(it).apply { scaleType = ImageView.ScaleType.CENTER_INSIDE } },
                        update = { view ->
                            view.setImageDrawable(runCatching { context.packageManager.getApplicationIcon(entry.packageName) }.getOrNull())
                        }
                    )
                    Column(Modifier.weight(1f)) {
                        Text(entry.label, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Text("UID ${entry.uid}", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(entry.packageName, fontSize = 9.sp, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(entry.installedAt, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("${if (english) "Risk" else "Riesgo"}: ${entry.riskLevel} ${entry.riskScore}/100", fontSize = 10.sp)
                if (entry.sharedUidPackages.isNotEmpty()) Text(if (english) "Shared UID: auto-block disabled to protect other packages." else "UID compartido: no se bloqueó automáticamente para no afectar otras apps.", fontSize = 10.sp, color = Color(0xFFB05A00))
                if (permissionGroups.isNotEmpty()) {
                    Spacer(Modifier.height(3.dp))
                    Text(if (english) "Permissions by group" else "Permisos agrupados", style = MaterialTheme.typography.labelMedium)
                    permissionGroups.forEach { group ->
                        Text("${group.label}: ${group.permissions.size}", fontSize = 9.sp)
                    }
                }
                Spacer(Modifier.height(4.dp))
                Row {
                    Button(onClick = { manager.review(context, entry.packageName, entry.uid, true, true); onChanged() }) {
                        Text(if (english) "Allow" else "Permitir", fontSize = 12.sp)
                    }
                    Spacer(Modifier.width(6.dp))
                    OutlinedButton(onClick = { manager.review(context, entry.packageName, entry.uid, false, false); onChanged() }) {
                        Text(if (english) "Keep blocked" else "Mantener bloqueada", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3) Post-update destination-anomaly watch
// ---------------------------------------------------------------------------
private fun updateWatchSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    item {
        var enabled by remember { mutableStateOf(AppNetworkProfileStore.isEnabled()) }
        var windowDays by remember { mutableStateOf(AppNetworkProfileStore.reviewWindowDays) }
        SectionCard {
            RowSwitch(if (english) "Watch apps after they update" else "Vigilar apps después de actualizarse", enabled) {
                enabled = it; AppNetworkProfileStore.setEnabled(context, it)
            }
            Text(
                if (english) "Builds a baseline of destinations each app normally talks to. If it contacts a destination it's never used before, shortly after an update, that's flagged here for review."
                else "Arma un perfil de a qué destinos habla normalmente cada app. Si contacta un destino que nunca usó antes, poco después de actualizarse, queda marcado acá para revisar.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(6.dp))
            Text(if (english) "Review window: $windowDays days after update" else "Ventana de revisión: $windowDays días después del update", fontSize = 11.sp)
            Slider(
                value = windowDays.toFloat(), onValueChange = { windowDays = it.toInt() },
                valueRange = 1f..30f, steps = 28,
                onValueChangeFinished = { AppNetworkProfileStore.reviewWindowDays = windowDays }
            )
        }
    }
    val anomalies = AppNetworkProfileStore.anomalySnapshot()
    item {
        Spacer(Modifier.height(8.dp))
        Text(if (english) "Flagged new destinations (${anomalies.size})" else "Destinos nuevos marcados (${anomalies.size})", style = MaterialTheme.typography.titleSmall)
    }
    if (anomalies.isEmpty()) {
        item { Text(if (english) "Nothing flagged." else "Nada marcado.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(anomalies.take(80)) { a ->
            SmallCard(background = Color(0xFFFCE9B5)) {
                Text(a.packageName, fontWeight = FontWeight.Bold, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                Text("${a.destination}:${a.port}", fontSize = 12.sp)
                Text(
                    if (english) "${"%.1f".format(a.daysSinceUpdate)} days after update • ${a.time}"
                    else "${"%.1f".format(a.daysSinceUpdate)} días después del update • ${a.time}",
                    fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = { AppNetworkProfileStore.dismissAnomaly(a.id); onChanged() }) {
                    Text(if (english) "Dismiss" else "Descartar", fontSize = 11.sp)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4) Doze/App Standby correlation
// ---------------------------------------------------------------------------
private fun dozeSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        SectionCard {
            Text(
                if (english) "Traffic that got through while the device was idle (Doze). Android already restricts most background network access in Doze, so an app that still gets through is worth a look."
                else "Tráfico que pasó mientras el teléfono estaba inactivo (Doze). Android ya restringe la mayoría del acceso de red en background durante Doze, así que una app que igual pasa merece revisión.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (english) "Requires the Traffic Analyzer to be turned on (Analyzer tab) to correlate against."
                else "Necesita que el Analizador de tráfico esté activo (pestaña Analizador) para poder correlacionar.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.Bold
            )
        }
    }
    val byApp = DozeAnomalyMonitor.byApp()
    item {
        Spacer(Modifier.height(8.dp))
        Text(if (english) "Apps active during Doze" else "Apps activas durante Doze", style = MaterialTheme.typography.titleSmall)
    }
    if (byApp.isEmpty()) {
        item { Text(if (english) "None observed." else "No se observó ninguna.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(byApp) { (pkg, count) ->
            SmallCard {
                Text(pkg, fontWeight = FontWeight.Bold, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                Text(
                    if (english) "$count data event(s) during idle" else "$count evento(s) de datos en inactivo",
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5) Service tamper log
// ---------------------------------------------------------------------------
private fun tamperSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    english: Boolean,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    item {
        SectionCard {
            Text(
                if (english) "Every time the VPN service stops without a matching in-app request (Stop button, kill switch, schedule), it's logged here. START_STICKY already restarts it, but a string of unexplained stops is worth noticing."
                else "Cada vez que el servicio VPN se detiene sin un pedido explícito desde la app (botón Detener, kill switch, horario), queda registrado acá. START_STICKY ya lo reinicia, pero una seguidilla de paradas sin explicación vale la pena notarla.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            TextButton(onClick = { ServiceTamperMonitor.clear(); onChanged() }) {
                Text(if (english) "Clear log" else "Limpiar registro", fontSize = 12.sp)
            }
        }
    }
    val events = ServiceTamperMonitor.eventsSnapshot()
    if (events.isEmpty()) {
        item { Text(if (english) "No unexpected stops recorded." else "No hay paradas inesperadas registradas.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(events) { e ->
            SmallCard(background = Color(0xFFF1D0D0)) {
                Text(e.note, fontSize = 12.sp)
                Text(e.time, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 6) Redundant/conflicting rule cleanup
// ---------------------------------------------------------------------------
private fun conflictsSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    english: Boolean,
    ipBlockStore: IpBlockStore,
    advancedRuleStore: AdvancedRuleStore,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    val findings = RuleConflictAnalyzer.analyze(ipBlockStore, advancedRuleStore)
    item {
        SectionCard {
            Text(
                if (english) "Scans your IP blocks and port rules for entries that are duplicated or already covered by a broader rule."
                else "Revisa tus bloqueos de IP y reglas de puerto en busca de entradas duplicadas o ya cubiertas por una regla más amplia.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (english) "${findings.size} finding(s)" else "${findings.size} hallazgo(s)",
                style = MaterialTheme.typography.titleSmall
            )
        }
    }
    if (findings.isEmpty()) {
        item { Text(if (english) "No redundant or conflicting rules found." else "No se encontraron reglas redundantes o en conflicto.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    } else {
        items(findings) { f ->
            SmallCard {
                Text(f.description, fontSize = 12.sp)
                if (f.removableIp != null || f.removablePortRule != null) {
                    TextButton(onClick = {
                        f.removableIp?.let { ipBlockStore.remove(it) }
                        f.removablePortRule?.let { advancedRuleStore.remove(it) }
                        onChanged()
                    }) { Text(if (english) "Remove redundant entry" else "Eliminar entrada redundante", fontSize = 11.sp) }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HYDRA SECURITY ENGINE — APK scanner
// ---------------------------------------------------------------------------
private fun apkScannerSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        var report by remember { mutableStateOf<ApkScanReport?>(null) }
        var scanning by remember { mutableStateOf(false) }
        val launcher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            scanning = true
            // APK analysis is local-only. No file is uploaded anywhere.
            Thread {
                val r = SecurityEngine(context).scanApk(uri)
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    report = r
                    scanning = false
                }
            }.start()
        }

        SectionCard {
            Text(if (english) "HYDRA SECURITY ENGINE" else "HYDRA SECURITY ENGINE", fontWeight = FontWeight.Bold, fontSize = 15.sp)
            Spacer(Modifier.height(4.dp))
            Text(
                if (english) "Analyze an APK locally: SHA-256, signing certificate, permissions, exported components, accessibility/device-admin capabilities, native code and a heuristic risk score. This is an analysis result, not proof of malware."
                else "Analiza una APK localmente: SHA-256, certificado de firma, permisos, componentes exportados, capacidades de accesibilidad/device-admin, código nativo y un nivel de riesgo heurístico. Es un resultado de análisis, no una prueba de malware.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            Button(onClick = { launcher.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, enabled = !scanning) {
                Text(if (scanning) (if (english) "Analyzing…" else "Analizando…") else (if (english) "Select APK" else "Seleccionar APK"))
            }
        }

        report?.let { r ->
            Spacer(Modifier.height(8.dp))
            SectionCard {
                Text(r.packageName ?: r.sourceName, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text("${r.versionName ?: "?"} • ${r.versionCode ?: "?"}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(5.dp))
                Text(
                    "${if (english) "RISK" else "RIESGO"}: ${r.risk.level} — ${r.risk.score}/100",
                    fontWeight = FontWeight.Bold,
                    color = when (r.risk.level) {
                        RiskLevel.SAFE -> Color(0xFF2E8B57)
                        RiskLevel.LOW -> Color(0xFF6E9F3A)
                        RiskLevel.MEDIUM -> Color(0xFFD98E1F)
                        RiskLevel.HIGH, RiskLevel.CRITICAL -> Color(0xFFC0392B)
                    }
                )
                Text("SHA-256\n${r.sha256}", fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                if (r.threatMatches.isEmpty()) {
                    Text(
                        if (english) "Threat signatures: no match" else "Firmas de amenazas: sin coincidencias",
                        fontSize = 10.sp, color = Color(0xFF2E8B57)
                    )
                } else {
                    Text(
                        if (english) "Threat signatures: ${r.threatMatches.size} match(es)" else "Firmas de amenazas: ${r.threatMatches.size} coincidencia(s)",
                        fontWeight = FontWeight.Bold, fontSize = 11.sp, color = Color(0xFFC0392B)
                    )
                    r.threatMatches.take(8).forEach { m ->
                        Text("• ${m.name} • ${m.family ?: "unknown"} • ${m.severity}", fontSize = 10.sp)
                        Text(m.detail, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (r.certificateSha256.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text(if (english) "Signing certificate" else "Certificado de firma", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    r.certificateSha256.take(3).forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 9.sp) }
                }
                Spacer(Modifier.height(5.dp))
                Text("${r.permissions.size} permisos • ${r.activities} activities • ${r.services} services • ${r.receivers} receivers • ${r.providers} providers", fontSize = 11.sp)
                Text("${if (english) "Exported" else "Exportados"}: ${r.exportedComponents} • Accessibility: ${r.accessibilityServices} • Device Admin: ${r.deviceAdminReceivers}", fontSize = 11.sp)
                Text("Overlay: ${if (r.hasOverlayPermission) "YES" else "NO"} • Install packages: ${if (r.canInstallPackages) "YES" else "NO"} • Debuggable: ${if (r.debuggable) "YES" else "NO"}", fontSize = 11.sp)
                Text("Native libs: ${r.nativeLibraries} • DEX: ${r.dexFiles} • splits: ${r.splitApkSha256.size}", fontSize = 11.sp)
                Text("Exported sin protección fuerte (no-Activity): ${r.exportedUnprotectedNonActivityComponents}", fontSize = 11.sp)
                Text("Cleartext: ${if (r.cleartextTrafficAllowed) "YES" else "NO"} • Network Security Config: ${if (r.hasNetworkSecurityConfig) "YES" else "NO"}", fontSize = 11.sp)
                if (r.installerPackageName != null || r.firstInstallTime > 0L) {
                    Text("Installer: ${r.installerPackageName ?: "?"}", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    when (r.baselineStatus) {
                        BaselineStatus.NOT_APPLICABLE -> if (english) "Baseline: not applicable to a standalone APK" else "Baseline: no aplica a una APK independiente"
                        BaselineStatus.FIRST_SEEN -> if (english) "Baseline: FIRST SEEN" else "Baseline: PRIMERA VEZ"
                        BaselineStatus.UNCHANGED -> if (english) "Baseline: unchanged" else "Baseline: sin cambios"
                        BaselineStatus.CHANGED -> if (english) "Baseline: CHANGE DETECTED" else "Baseline: CAMBIO DETECTADO"
                    },
                    fontWeight = FontWeight.Bold,
                    color = if (r.baselineStatus == BaselineStatus.CHANGED) Color(0xFFC0392B) else MaterialTheme.colorScheme.onSurface
                )
                r.baselineChanges.take(6).forEach { Text("• $it", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                if (r.baselineStatus == BaselineStatus.CHANGED && r.packageName != null) {
                    Button(onClick = {
                        SecurityEngine(context).acceptBaseline(r)
                        report = r.copy(
                            baselineStatus = BaselineStatus.UNCHANGED,
                            baselineChanges = emptyList()
                        )
                    }) { Text(if (english) "Accept current state as baseline" else "Aceptar estado actual como baseline", fontSize = 10.sp) }
                }
            }

            r.mh100kAi?.let { ai ->
                Spacer(Modifier.height(6.dp))
                SmallCard {
                    Text(
                        if (english) "MH-100K static security AI" else "IA estática de seguridad MH-100K",
                        fontWeight = FontWeight.Bold, fontSize = 12.sp
                    )
                    Text(
                        if (english) "Secondary static-analysis signal: ${ai.score}/100" else "Señal secundaria de análisis estático: ${ai.score}/100",
                        fontWeight = FontWeight.Bold, fontSize = 18.sp
                    )
                    Text(
                        if (english) "Matched model features: ${ai.matchedFeatures}/${ai.modelFeatureCount} • extracted: ${ai.extractedFeatureCount} • DEX analyzed: ${ai.dexFilesAnalyzed}"
                        else "Features activas del modelo: ${ai.matchedFeatures}/${ai.modelFeatureCount} • extraídas: ${ai.extractedFeatureCount} • DEX analizados: ${ai.dexFilesAnalyzed}",
                        fontSize = 10.sp
                    )
                    Text(
                        if (english) "Observed API calls: ${ai.apiCallsObserved} • permissions: ${ai.permissionFeaturesObserved} • intents: ${ai.intentFeaturesObserved}"
                        else "Llamadas API observadas: ${ai.apiCallsObserved} • permisos: ${ai.permissionFeaturesObserved} • intents: ${ai.intentFeaturesObserved}",
                        fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (ai.extractionIncomplete) {
                        Text(
                            if (english) "Static extraction was bounded; some DEX content may not have been analyzed."
                            else "El análisis estático fue acotado; parte del contenido DEX puede no haberse analizado.",
                            fontSize = 10.sp, color = MaterialTheme.colorScheme.error
                        )
                    }
                    Text(
                        if (english) "Model ${ai.modelVersion}. This score is not a calibrated probability and is not an automatic malware verdict or blocking authority."
                        else "Modelo ${ai.modelVersion}. Este puntaje no es una probabilidad calibrada ni un veredicto automático de malware y no puede bloquear por sí solo.",
                        fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (r.risk.indicators.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(if (english) "Indicators" else "Indicadores", style = MaterialTheme.typography.titleSmall)
                r.risk.indicators.forEach { ind ->
                    SmallCard {
                        Text("${ind.severity} • ${ind.title} • +${ind.points}", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                        Text(ind.detail, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (r.permissions.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(if (english) "Requested permissions" else "Permisos solicitados", style = MaterialTheme.typography.titleSmall)
                r.permissions.forEach { perm -> Text(perm, fontFamily = FontFamily.Monospace, fontSize = 9.sp, modifier = Modifier.padding(vertical = 1.dp)) }
            }
            if (r.staticSecurityHints.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                SmallCard {
                    Text(if (english) "Static security hints" else "Indicadores estáticos", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    r.staticSecurityHints.take(20).forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 9.sp) }
                }
            }
            if (r.errors.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                SmallCard(background = Color(0xFFFFE7C2)) {
                    Text(if (english) "Scanner notes" else "Notas del analizador", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    r.errors.forEach { Text(it, fontSize = 10.sp) }
                }
            }
        }

        Spacer(Modifier.height(10.dp))
        val events = SecurityEventStore.snapshot(context).take(20)
        Text(if (english) "Security Engine events" else "Eventos del Security Engine", style = MaterialTheme.typography.titleSmall)
        if (events.isEmpty()) Text(if (english) "No events yet." else "Todavía no hay eventos.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        else events.forEach { e ->
            SmallCard {
                Text("${e.severity} • ${e.title}", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                Text(e.detail, fontSize = 10.sp)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HYDRA SECURITY ENGINE — behavior correlation
// ---------------------------------------------------------------------------
private fun behaviorSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        SectionCard {
            Text(if (english) "Behavior correlation" else "Correlación de comportamiento", fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(
                if (english) "Correlates metadata already collected by Hydra: connections, destinations, DNS blocks, unusual ports and known-bad TLS fingerprints. It never changes firewall decisions."
                else "Correlaciona metadatos que Hydra ya recopila: conexiones, destinos, bloqueos DNS, puertos poco habituales y huellas TLS conocidas como malas. No modifica las decisiones del firewall.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        HydraAiEngine.init(context)
        HydraPrivacyAiEngine.init(context)
        val behaviors = BehaviorRiskAnalyzer.analyze(context, TrafficAnalyzerStore.snapshot(), TlsFingerprintStore.snapshot()).take(30)
        if (behaviors.isEmpty()) {
            Text(if (english) "No analyzer data yet. Enable the traffic analyzer and use the device normally." else "Todavía no hay datos. Activá el analizador de tráfico y usá el dispositivo normalmente.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            behaviors.forEach { b ->
                SmallCard {
                    Text("${b.level} • ${b.packageName} • ${b.score}/100", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text(
                        if (english) "connections=${b.connections} • destinations=${b.uniqueDestinations} • DNS=${b.dnsQueries} • DNS blocks=${b.dnsBlocks}"
                        else "conexiones=${b.connections} • destinos=${b.uniqueDestinations} • DNS=${b.dnsQueries} • bloqueos DNS=${b.dnsBlocks}",
                        fontSize = 10.sp
                    )
                    Text(
                        if (english) "TLS alerts=${b.tlsAlerts} • unusual ports=${b.unusualPorts} • recent=${b.recentConnections} • new destinations=${b.baselineNewDestinations}"
                        else "alertas TLS=${b.tlsAlerts} • puertos inusuales=${b.unusualPorts} • recientes=${b.recentConnections} • destinos nuevos=${b.baselineNewDestinations}",
                        fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(if (english) "Why this score" else "Por qué este puntaje", fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 4.dp))
                    val reasons = buildList {
                        if (b.connections >= 500) {
                            add(if (english) "High connection volume (+8)" else "Volumen alto de conexiones (+8)")
                        } else if (b.connections >= 100) {
                            add(if (english) "Elevated connection volume (+5)" else "Volumen elevado de conexiones (+5)")
                        } else if (b.connections >= 25) {
                            add(if (english) "Moderate connection volume (+3)" else "Volumen moderado de conexiones (+3)")
                        }
                        if (b.uniqueDestinations >= 100) {
                            add(if (english) "Very diverse destinations (+6)" else "Muchos destinos diferentes (+6)")
                        } else if (b.uniqueDestinations >= 30) {
                            add(if (english) "High destination diversity (+4)" else "Alta diversidad de destinos (+4)")
                        } else if (b.uniqueDestinations >= 10) {
                            add(if (english) "Destination diversity (+2)" else "Diversidad de destinos (+2)")
                        }
                        if (b.dnsBlocks > 0) add(if (english) "DNS blocks (${b.dnsBlocks})" else "Bloqueos DNS (${b.dnsBlocks})")
                        if (b.tlsAlerts > 0) add(if (english) "Known-bad TLS fingerprint matches (${b.tlsAlerts})" else "Coincidencias con huellas TLS conocidas como peligrosas (${b.tlsAlerts})")
                        if (b.unusualPorts > 0) add(if (english) "Unusual ports (${b.unusualPorts})" else "Puertos inusuales (${b.unusualPorts})")
                        if (b.recentConnections >= 30) add(if (english) "Recent burst (${b.recentConnections} in 15 min)" else "Pico reciente (${b.recentConnections} en 15 min)")
                        if (b.baselineNewDestinations > 0) add(if (english) "New destinations (${b.baselineNewDestinations})" else "Destinos nuevos (${b.baselineNewDestinations})")
                    }.take(5)
                    if (reasons.isEmpty()) Text(if (english) "No elevated indicators." else "No hay indicadores elevados.", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    else reasons.forEach { Text("• $it", fontSize = 10.sp) }
                    if (b.aiScore != null) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (english) "Security intelligence: ${b.aiLevel} • ${b.aiScore}/100" else "Inteligencia de seguridad: ${b.aiLevel} • ${b.aiScore}/100",
                            fontSize = 10.sp, fontWeight = FontWeight.Bold
                        )
                        Text(
                            b.aiExplanation.orEmpty(),
                            fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (b.privacyScore != null) {
                        Spacer(Modifier.height(3.dp))
                        Text(
                            if (english) "Privacy / tracking: ${b.privacyLevel} • ${b.privacyScore}/100" else "Privacidad / tracking: ${b.privacyLevel} • ${b.privacyScore}/100",
                            fontSize = 10.sp, fontWeight = FontWeight.Bold
                        )
                        Text(
                            b.privacyExplanation.orEmpty(),
                            fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        if (english) "Confidence: ${if (b.connections >= 100) "medium" else "low"} • This is a review signal, not a malware verdict."
                        else "Confianza: ${if (b.connections >= 100) "media" else "baja"} • Es una señal para revisar, no un veredicto de malware.",
                        fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 3.dp)
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 10) Unified security timeline
// ---------------------------------------------------------------------------
private fun timelineSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        val analyzer = TrafficAnalyzerStore.snapshot().map { e ->
            TimelineItem(e.timestamp, "NETWORK", e.packageName ?: "uid:${e.uid}", "${e.kind} • ${e.protocol} ${e.destination}:${e.port}")
        }
        val security = SecurityEventStore.snapshot(context).map { e ->
            TimelineItem(e.time, e.severity.name, e.title, e.detail)
        }
        val items = (analyzer + security).sortedByDescending { it.time }.take(80)
        SectionCard {
            Text(if (english) "Unified security timeline" else "Línea de tiempo de seguridad", fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(
                if (english) "Network and security events are shown together so an alert can be correlated with what happened before and after it."
                else "Los eventos de red y seguridad se muestran juntos para correlacionar una alerta con lo que ocurrió antes y después.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (items.isEmpty()) {
            Text(if (english) "No events yet." else "Todavía no hay eventos.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            items.forEach { e ->
                SmallCard {
                    Text("${java.text.SimpleDateFormat("HH:mm:ss", Locale.US).format(java.util.Date(e.time))} • ${e.type}", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    Text(e.title, fontSize = 11.sp)
                    Text(e.detail, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

private data class TimelineItem(val time: Long, val type: String, val title: String, val detail: String)

// ---------------------------------------------------------------------------
// Small shared building blocks
// ---------------------------------------------------------------------------
@Composable
private fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(10.dp),
        content = content
    )
}

@Composable
private fun SmallCard(background: Color? = null, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(background ?: MaterialTheme.colorScheme.surface)
            .padding(8.dp),
        content = content
    )
}

@Composable
private fun RowSwitch(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, fontSize = 13.sp, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
