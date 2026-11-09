package com.hydra.firewall

import android.content.Context
import com.hydra.firewall.ui.theme.HydraCard
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
fun SecurityCenterTab(context: Context, language: AppLanguage, advancedMode: Boolean = false, onEnableAdvanced: () -> Unit = {}) {
    val english = language.isEnglish() ||
        (language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
    var refreshTrigger by remember { mutableStateOf(0) }
    val ipBlockStore = remember { IpBlockStore(context) }
    val advancedRuleStore = remember { AdvancedRuleStore(context) }
    val quarantineManager = remember { QuarantineManager(context) }

    var picked by remember { mutableStateOf(SecuritySection.STATUS) }
    // Normal mode is a single screen; the section picker only exists in Advanced mode.
    val section = if (advancedMode) picked else SecuritySection.STATUS

    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 10.dp, vertical = 6.dp)) {
        item {
            Text(
                if (english) "Security" else "Seguridad",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (advancedMode) {
                    if (english) "Protection status, quarantine, update watch, APK scanner (experimental), traffic correlation and Doze."
                    else "Estado de la protección, cuarentena, vigilancia de updates, analizador APK (experimental), correlación de tráfico y Doze."
                } else {
                    if (english) "Is your phone protected, and which apps deserve a look."
                    else "Si tu teléfono está protegido y qué apps conviene revisar."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (advancedMode) {
                Spacer(Modifier.height(8.dp))
                SecuritySectionPicker(section, english) { picked = it; refreshTrigger++ }
            }
            Spacer(Modifier.height(8.dp))
        }

        when (section) {
            SecuritySection.STATUS -> {
                statusSection(this, context, english, quarantineManager, refreshTrigger, advancedMode)
                tamperNotice(this, english, refreshTrigger) { refreshTrigger++ }
                if (!advancedMode) {
                    // One screen for everyone else: quarantine and update watch live right here.
                    quarantineSection(this, context, english, quarantineManager, refreshTrigger) { refreshTrigger++ }
                    updateWatchSection(this, context, english, refreshTrigger) { refreshTrigger++ }
                }
                securityHistory(this, context, english, refreshTrigger)
                if (!advancedMode) {
                    item {
                        ModernCard {
                            Text(if (english) "Want more tools?" else "¿Querés más herramientas?", fontWeight = FontWeight.Bold)
                            Text(
                                if (english) "Advanced mode adds the APK scanner, traffic correlation, IP and port rules, profiles and more technical detail."
                                else "El modo Avanzado agrega el analizador APK, la correlación de tráfico, reglas de IP y puertos, perfiles y más detalle técnico.",
                                fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = onEnableAdvanced) {
                                Text(if (english) "Turn on Advanced mode" else "Activar modo Avanzado")
                            }
                        }
                    }
                }
            }
            SecuritySection.APK_SCANNER -> apkScannerSection(this, context, english, refreshTrigger)
            SecuritySection.BEHAVIOR -> behaviorSection(this, context, english, refreshTrigger)
            SecuritySection.QUARANTINE -> quarantineSection(this, context, english, quarantineManager, refreshTrigger) { refreshTrigger++ }
            SecuritySection.UPDATE_WATCH -> updateWatchSection(this, context, english, refreshTrigger) { refreshTrigger++ }
            SecuritySection.DOZE -> dozeSection(this, english, refreshTrigger)
        }

        item { Spacer(Modifier.height(24.dp)) }
    }
}


@Composable
private fun ModernCard(content: @Composable ColumnScope.() -> Unit) {
    HydraCard(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
    }
}

@Composable
private fun StatusChip(text: String) {
    Text(
        text, fontSize = 11.sp, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(50)).background(MaterialTheme.colorScheme.surfaceVariant).padding(horizontal = 10.dp, vertical = 5.dp)
    )
}

@Composable
private fun LayerRow(
    title: String, sub: String, ok: Boolean?, checked: Boolean?, onChecked: ((Boolean) -> Unit)?,
    content: @Composable ColumnScope.() -> Unit = {}
) {
    ModernCard {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(10.dp).clip(RoundedCornerShape(5.dp)).background(
                    when (ok) { true -> Color(0xFF34D399); false -> Color(0xFFF87171); null -> Color(0xFF8A8A99) }
                )
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.Bold)
                Text(sub, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (checked != null && onChecked != null) {
                Spacer(Modifier.width(8.dp))
                Switch(checked = checked, onCheckedChange = onChecked)
            }
        }
        content()
    }
}

/** The single place to switch on/off and update each protection layer. Nothing here is repeated elsewhere. */
@Composable
private fun ControlPanelCard(context: Context, english: Boolean, refreshTrigger: Int) {
    val main = remember { android.os.Handler(android.os.Looper.getMainLooper()) }
    fun t(es: String, en: String) = if (english) en else es
    var tick by remember { mutableStateOf(0) }
    var vpnOn by remember(refreshTrigger) { mutableStateOf(FirewallVpnService.isRunning) }
    var packOn by remember(refreshTrigger) { mutableStateOf(ThreatSignatureStore.isEnabled(context)) }
    var packDetails by remember { mutableStateOf(false) }
    var avOn by remember(refreshTrigger) { mutableStateOf(AppThreatScanner.isAutoEnabled(context)) }
    var avBusy by remember { mutableStateOf(AppThreatScanner.isFullScanRunning()) }
    var avMsg by remember { mutableStateOf("") }
    var allBusy by remember { mutableStateOf(false) }
    var found by remember(tick, refreshTrigger) { mutableStateOf(AppThreatScanner.findings(context)) }
    var updAuto by remember { mutableStateOf(AppUpdater.isAutoEnabled(context)) }
    var updBusy by remember { mutableStateOf(false) }
    var updMsg by remember { mutableStateOf("") }
    var updOk by remember { mutableStateOf<Boolean?>(null) }
    var updRelease by remember { mutableStateOf<AppUpdater.Release?>(null) }
    var ignoredList by remember(tick, refreshTrigger) { mutableStateOf(AppThreatScanner.ignoredFindings(context)) }
    var showIgnored by remember { mutableStateOf(false) }
    var behavior by remember(tick, refreshTrigger) { mutableStateOf(AppThreatScanner.behaviorFindings(context)) }
    var ignoredBehavior by remember(tick, refreshTrigger) { mutableStateOf(AppThreatScanner.ignoredBehavior(context)) }
    // The scan can also be started in the background (on app open, after a pack update): follow its real state so the
    // button is enabled again as soon as it ends (the old value was read once and could stay disabled forever).
    var uiTick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        var wasBusy = false
        while (true) {
            val running = AppThreatScanner.isFullScanRunning()
            val updating = ThreatSignatureUpdater.isUpdating()
            if (avBusy != running && !allBusy) { avBusy = running; if (!running) tick++ }
            val busyNow = running || updating
            if (busyNow || wasBusy) uiTick++   // redraw progress while busy, and once more when it ends
            wasBusy = busyNow
            kotlinx.coroutines.delay(1000)
        }
    }
    @Suppress("UNUSED_VARIABLE") val redraw = uiTick
    // Update progress (download %, verifying, installing): redraw quickly while an update is in progress.
    var updTick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            if (AppUpdater.phase() != AppUpdater.Phase.IDLE) updTick++
            kotlinx.coroutines.delay(300)
        }
    }
    @Suppress("UNUSED_VARIABLE") val redrawUpd = updTick
    val updPhase = AppUpdater.phase()
    val packUpdating = ThreatSignatureUpdater.isUpdating()
    val scanning = AppThreatScanner.isFullScanRunning()
    val (scanDone, scanTotal) = AppThreatScanner.progress()
    val busyAny = packUpdating || scanning || allBusy
    val lastFull = AppThreatScanner.lastFullScan(context)
    val dateFmt = java.text.DateFormat.getDateTimeInstance()
    val debugBuild = remember { AppUpdater.isDebugBuild(context) }

    fun friendly(err: String): String = when {
        err.contains("signature_differs") -> t("La firma del APK nuevo no coincide con la de esta instalación. Hay que instalar UNA vez la versión release firmada con tu clave (desinstalando esta); desde ahí se actualiza sola.", "The new APK's signature differs from this install. Install the signed release build ONCE (uninstall this one); after that it updates itself.") + " " + err.substringAfter("signature_differs", "").trim()
        err.contains("sha256") -> t("La descarga no coincide con el SHA‑256 publicado: se descartó.", "The download does not match the published SHA‑256: discarded.")
        err.contains("not_newer") -> {
            fun name(code: Long) = "${code / 10000}.${(code / 100) % 100}.${code % 100}"
            val m = Regex("not_newer:(\\d+):(\\d+)").find(err)
            if (m != null) {
                val newer = m.groupValues[1].toLong(); val own = m.groupValues[2].toLong()
                t("El APK descargado es la versión ${name(newer)} (código $newer) y ya tenés la ${name(own)} (código $own). Si acabás de publicar, revisá que el tag salga de un commit con la versión nueva.",
                  "The downloaded APK is version ${name(newer)} (code $newer) and you already have ${name(own)} (code $own). If you just published, check that the tag points to a commit with the new version.")
            } else t("Esa versión no es más nueva que la instalada.", "That version is not newer than the installed one.")
        }
        else -> err
    }

    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // ---- status header
        val attention = found.size
        val headline = when {
            busyAny && attention == 0 -> t("Preparando la protección…", "Getting protection ready…")
            attention > 0 -> t("$attention app(s) requieren atención", "$attention app(s) need attention")
            lastFull == 0L -> t("Todavía no se revisaron las apps", "Apps not checked yet")
            else -> t("Estás protegido", "You are protected")
        }
        val headColor = if (attention > 0) Color(0xFFF87171) else if (busyAny || lastFull == 0L) Color(0xFFFBBF24) else Color(0xFF34D399)
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp))
                .background(androidx.compose.ui.graphics.Brush.verticalGradient(listOf(headColor.copy(alpha = 0.30f), MaterialTheme.colorScheme.surface)))
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(48.dp).clip(androidx.compose.foundation.shape.CircleShape).background(headColor),
                    contentAlignment = Alignment.Center
                ) { Text(if (attention > 0) "!" else if (busyAny) "…" else if (lastFull == 0L) "?" else "✓", fontSize = 26.sp, fontWeight = FontWeight.Bold, color = Color(0xFF10131A)) }
                Spacer(Modifier.width(12.dp))
                Text(headline, fontWeight = FontWeight.Bold, fontSize = 20.sp)
            }
            Text(
                (if (attention > 0) t("Coinciden con amenazas conocidas", "Match known threats") else t("0 amenazas conocidas", "0 known threats")) +
                    " • " + (if (lastFull == 0L) t("sin revisión completa", "no full check yet") else t("última revisión ", "last check ") + dateFmt.format(java.util.Date(lastFull))),
                fontSize = 12.sp
            )
            if (busyAny) {
                Text(
                    when {
                        packUpdating -> t("Descargando y verificando el pack de amenazas…", "Downloading and verifying the threat pack…")
                        scanning && scanTotal > 0 -> t("Revisando tus apps contra el pack: $scanDone de $scanTotal…", "Checking your apps against the pack: $scanDone of $scanTotal…")
                        scanning -> t("Preparando la revisión de apps…", "Preparing the app check…")
                        else -> t("Revisando…", "Checking…")
                    },
                    fontSize = 13.sp, fontWeight = FontWeight.Medium
                )
                Text(
                    t("Los botones «Revisar» se activan cuando termina y aparece «Estás protegido». Pasa solo tras instalar o actualizar; puede tardar unos minutos según cuántas apps tengas.",
                      "The “Check” buttons turn on when it finishes and “You are protected” appears. This happens by itself after installing or updating; it can take a few minutes depending on how many apps you have."),
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StatusChip(if (vpnOn) t("VPN activa", "VPN on") else t("VPN apagada", "VPN off"))
                StatusChip("Pack " + ThreatSignatureStore.activePackVersion())
                StatusChip("Hydra " + AppUpdater.currentVersion())
            }
            Button(modifier = Modifier.fillMaxWidth(), enabled = !busyAny, onClick = {
                allBusy = true; avMsg = t("Revisando…", "Checking…")
                ThreatSignatureUpdater.updateIfDue(context, force = true) { _ ->
                    val started = AppThreatScanner.scanAll(context, force = true, onDone = { list ->
                        main.post {
                            allBusy = false; tick++
                            avMsg = if (list.isEmpty()) t("✅ Todo revisado: sin amenazas conocidas.", "✅ All checked: no known threats.")
                            else t("Amenazas encontradas: ${list.size}", "Threats found: ${list.size}")
                        }
                    })
                    if (!started) main.post { allBusy = false }
                }
            }) { Text(if (busyAny) (if (scanning && scanTotal > 0) t("Revisando $scanDone/$scanTotal…", "Checking $scanDone/$scanTotal…") else t("Espere, preparando…", "Please wait, preparing…")) else t("Revisar todo ahora", "Check everything now")) }
        }

        // ---- findings first (what needs action)
        found.forEach { f ->
            ModernCard {
                Text((if (f.definitive) "⚠ " else "? ") + f.label, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(f.packageName, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(
                    f.matches.take(3).joinToString(", ") { it.name } +
                        if (f.definitive) t(" — hash exacto de malware conocido", " — exact known-malware hash")
                        else t(" — solo patrón, puede ser falso positivo", " — pattern only, may be a false positive"),
                    fontSize = 12.sp
                )
                Text(AppThreatScanner.plainReason(f, english), fontSize = 13.sp, fontWeight = FontWeight.Medium)
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF87171), contentColor = Color(0xFF3B0B0B)),
                    onClick = {
                        runCatching {
                            context.startActivity(android.content.Intent(android.content.Intent.ACTION_DELETE, Uri.parse("package:" + f.packageName))
                                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                        }
                    }
                ) { Text(t("Desinstalar…", "Uninstall…")) }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = {
                        Thread {
                            val text = runCatching { AppThreatScanner.detailsText(context, f) }.getOrDefault(f.packageName)
                            main.post {
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("Hydra app report", text))
                                android.widget.Toast.makeText(context, t("Datos copiados", "Details copied"), android.widget.Toast.LENGTH_SHORT).show()
                            }
                        }.start()
                    }) { Text(t("Copiar datos", "Copy details"), fontSize = 12.sp, maxLines = 1) }
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = {
                        runCatching {
                            context.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, Uri.parse(AppThreatScanner.googleQuery(f)))
                                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                        }
                    }) { Text(t("Buscar en Google", "Search Google"), fontSize = 12.sp, maxLines = 1) }
                }
                OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = {
                    AppThreatScanner.ignore(context, f); tick++
                    android.widget.Toast.makeText(context, t("Ignorada. Podés volver a vigilarla desde «Apps ignoradas».", "Ignored. You can watch it again from “Ignored apps”."), android.widget.Toast.LENGTH_LONG).show()
                }) { Text(t("Ignorar (no es un problema)", "Ignore (not a problem)")) }
                Text(t("Hydra nunca borra nada sola: decidís vos.", "Hydra never removes anything by itself: you decide."), fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // ---- Ignored apps
        if (ignoredList.isNotEmpty()) {
            ModernCard {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(t("Apps ignoradas (${ignoredList.size})", "Ignored apps (${ignoredList.size})"), fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                    TextButton(onClick = { showIgnored = !showIgnored }) { Text(if (showIgnored) t("Ocultar", "Hide") else t("Ver", "Show")) }
                }
                if (showIgnored) {
                    ignoredList.forEach { f ->
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(f.label, fontWeight = FontWeight.Bold)
                            Text(f.packageName + " • " + f.matches.take(2).joinToString(", ") { it.name }, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(t("Ignorada el ", "Ignored on ") + dateFmt.format(java.util.Date(f.time)), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { AppThreatScanner.unignore(context, f.packageName); tick++ }) {
                                Text(t("Volver a vigilar", "Watch again"))
                            }
                        }
                    }
                    Text(t("Si una app ignorada cambia su firma de desarrollador, Hydra la vuelve a vigilar y te avisa.", "If an ignored app changes its developer signature, Hydra watches it again and notifies you."), fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        // ---- Sensitive-permission indications (sideloaded apps only)
        behavior.forEach { b ->
            ModernCard {
                Text("🔎 " + b.label, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(b.packageName, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                b.indicators.forEach { i ->
                    Text("• " + (if (english) i.en else i.es), fontSize = 12.sp)
                }
                Text(t("No es una prueba de malware: muchas apps legítimas piden estos permisos. Revisá si la instalaste vos y si la necesitás.", "This is not proof of malware: many legitimate apps request these permissions. Check that you installed it and still need it."), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = {
                        runCatching {
                            context.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode(b.label + " " + b.packageName + " android permissions safe")))
                                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                        }
                    }) { Text(t("Buscar en Google", "Search Google"), fontSize = 12.sp, maxLines = 1) }
                    OutlinedButton(modifier = Modifier.weight(1f), onClick = {
                        AppThreatScanner.ignoreBehavior(context, b); tick++
                    }) { Text(t("Ignorar", "Ignore"), fontSize = 12.sp, maxLines = 1) }
                }
            }
        }
        if (ignoredBehavior.isNotEmpty()) {
            ModernCard {
                Text(t("Permisos delicados ignorados (${ignoredBehavior.size})", "Ignored sensitive-permission apps (${ignoredBehavior.size})"), fontWeight = FontWeight.Bold)
                ignoredBehavior.forEach { b ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(b.label, fontWeight = FontWeight.Bold)
                        Text(b.packageName + " • " + t("ignorada el ", "ignored on ") + dateFmt.format(java.util.Date(b.time)), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { AppThreatScanner.unignoreBehavior(context, b.packageName); tick++ }) {
                            Text(t("Volver a vigilar", "Watch again"))
                        }
                    }
                }
            }
        }

        // ---- Antivirus
        LayerRow(
            t("Antivirus", "Antivirus"),
            t("Revisa apps nuevas solo • última completa: ", "Checks new apps by itself • last full: ") + (if (lastFull == 0L) "-" else dateFmt.format(java.util.Date(lastFull))),
            if (found.isEmpty()) true else false, avOn, { avOn = it; AppThreatScanner.setAutoEnabled(context, it) }
        ) {
            OutlinedButton(modifier = Modifier.fillMaxWidth(), enabled = !busyAny, onClick = {
                avBusy = true; avMsg = t("Revisando…", "Checking…")
                val started = AppThreatScanner.scanAll(context, force = true, onDone = { list ->
                    main.post {
                        avBusy = false; tick++
                        avMsg = if (list.isEmpty()) t("✅ Ya está todo revisado: sin amenazas conocidas.", "✅ All checked: no known threats.")
                        else t("Amenazas encontradas: ${list.size}", "Threats found: ${list.size}")
                    }
                })
                if (!started) avBusy = false
            }) { Text(if (busyAny) t("Revisión en curso…", "Check in progress…") else t("Revisar apps ahora", "Check apps now")) }
            if (busyAny) Text(t("Deshabilitado mientras se actualiza el pack o se revisan las apps (ver arriba).", "Disabled while the pack updates or apps are being checked (see above)."), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (avMsg.isNotEmpty()) Text(avMsg, fontSize = 12.sp)
        }

        // ---- Threat pack
        LayerRow(
            t("Pack de amenazas", "Threat pack"),
            t("Versión ", "Version ") + ThreatSignatureStore.activePackVersion() + t(" • se actualiza solo cada ~24 h", " • updates itself every ~24 h"),
            true, packOn, { packOn = it; ThreatSignatureStore.setEnabled(context, it) }
        ) {
            TextButton(onClick = { packDetails = !packDetails }) {
                Text(if (packDetails) t("Ocultar detalles y actualizar", "Hide details and update") else t("Ver detalles y actualizar", "Details and update"), fontSize = 12.sp)
            }
            if (packDetails) ThreatPackCard(english, refreshTrigger + tick)
        }

        // ---- Hydra itself
        LayerRow(
            t("Actualización de Hydra", "Hydra update"),
            when {
                updMsg.isNotEmpty() -> updMsg
                AppUpdater.recentUpdateFrom(context) != null ->
                    t("✅ Hydra se actualizó (${AppUpdater.recentUpdateFrom(context)} → ${AppUpdater.currentVersion()})", "✅ Hydra was updated (${AppUpdater.recentUpdateFrom(context)} → ${AppUpdater.currentVersion()})")
                else -> t("Versión ${AppUpdater.currentVersion()}", "Version ${AppUpdater.currentVersion()}") +
                    (AppUpdater.lastCheck(context).takeIf { it > 0L }?.let { " • " + t("última búsqueda ", "last check ") + dateFmt.format(java.util.Date(it)) } ?: "")
            },
            updOk, updAuto, { updAuto = it; AppUpdater.setAutoEnabled(context, it) }
        ) {
            OutlinedButton(modifier = Modifier.fillMaxWidth(), enabled = !updBusy, onClick = {
                updBusy = true; updMsg = t("Buscando…", "Checking…"); updRelease = null; updOk = null
                AppUpdater.check(context) { r ->
                    main.post {
                        updBusy = false
                        when (r) {
                            is AppUpdater.CheckResult.UpToDate -> { updOk = true; updMsg = t("✅ Ya está actualizado (versión ${r.current}). No hay versiones nuevas.", "✅ Already up to date (version ${r.current}). No new versions.") }
                            is AppUpdater.CheckResult.Available -> { updOk = false; updRelease = r.release; updMsg = t("Hay una versión nueva: ${r.release.version}", "New version available: ${r.release.version}") }
                            is AppUpdater.CheckResult.Error -> { updOk = false; updMsg = t("No se pudo buscar: ", "Could not check: ") + friendly(r.message) }
                        }
                    }
                }
            }) { Text(t("Buscar actualización", "Check for update")) }
            if (updPhase != AppUpdater.Phase.IDLE) {
                val done = AppUpdater.downloaded(); val total = AppUpdater.expected()
                val frac = AppUpdater.fraction(done, total)
                fun mb(b: Long) = String.format(java.util.Locale.US, "%.1f", b / 1048576.0)
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        when (updPhase) {
                            AppUpdater.Phase.DOWNLOADING ->
                                t("⬇ Descargando", "⬇ Downloading") + (if (frac != null) " ${(frac * 100).toInt()}% (${mb(done)} / ${mb(total)} MB)" else " ${mb(done)} MB")
                            AppUpdater.Phase.VERIFYING -> t("🔍 Verificando la descarga y la firma…", "🔍 Verifying the download and signature…")
                            AppUpdater.Phase.INSTALLING -> t("⚙ Instalando… Hydra se va a reiniciar sola y la VPN vuelve a arrancar. No la cierres.", "⚙ Installing… Hydra will restart by itself and the VPN comes back. Do not close it.")
                            else -> t("👆 Android espera tu confirmación para instalar", "👆 Android is waiting for your confirmation to install")
                        },
                        fontWeight = FontWeight.Bold, fontSize = 13.sp
                    )
                    if (updPhase == AppUpdater.Phase.DOWNLOADING && frac != null) {
                        LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
                    } else if (updPhase != AppUpdater.Phase.CONFIRM) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
            }
            updRelease?.let { rel ->
                Button(modifier = Modifier.fillMaxWidth(), enabled = !updBusy && updPhase == AppUpdater.Phase.IDLE, onClick = {
                    updBusy = true; updMsg = t("Descargando y verificando…", "Downloading and verifying…")
                    AppUpdater.downloadAndInstall(context, rel, background = false) { err ->
                        main.post {
                            updBusy = false
                            updMsg = if (err == null) t("Verificada. Android te pedirá confirmar la instalación.", "Verified. Android will ask you to confirm the install.")
                            else t("Falló: ", "Failed: ") + friendly(err)
                        }
                    }
                }) { Text(t("Descargar e instalar ${rel.version}", "Download and install ${rel.version}")) }
            }
            Text(
                (if (debugBuild) t("Esta instalación es una compilación de PRUEBA (debug): no se puede actualizar con el APK release; instalá una vez hydra-release-apk.", "This install is a TEST (debug) build: it cannot be updated by the release APK; install hydra-release-apk once.")
                else t("Compilación release", "Release build")) + " • " + t("firma ", "signature ") + AppUpdater.ownCertShort(context),
                fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(t("Solo instala versiones con la misma firma; Android siempre pide confirmar.", "Only installs same-signature versions; Android always asks to confirm."), fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private enum class SecuritySection { STATUS, QUARANTINE, UPDATE_WATCH, APK_SCANNER, BEHAVIOR, DOZE }

private val TOOL_SECTIONS = listOf(SecuritySection.APK_SCANNER, SecuritySection.BEHAVIOR, SecuritySection.DOZE)

@Composable
private fun SectionChip(label: String, selected: Boolean, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label, fontSize = 11.sp) },
        colors = AssistChipDefaults.assistChipColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.18f) else MaterialTheme.colorScheme.surfaceVariant,
            labelColor = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
        ),
        modifier = Modifier.padding(end = 6.dp)
    )
}

/** Four main sections; the experimental / technical ones live together under "Tools". */
@Composable
private fun SecuritySectionPicker(current: SecuritySection, english: Boolean, onPick: (SecuritySection) -> Unit) {
    val main = listOf(
        SecuritySection.STATUS to (if (english) "Protection" else "Protección"),
        SecuritySection.QUARANTINE to (if (english) "Quarantine" else "Cuarentena"),
        SecuritySection.UPDATE_WATCH to (if (english) "Update watch" else "Vigilar updates")
    )
    val toolLabels = mapOf(
        SecuritySection.APK_SCANNER to (if (english) "APK scanner (experimental)" else "Analizar APK (experimental)"),
        SecuritySection.BEHAVIOR to (if (english) "Traffic correlation" else "Correlación de tráfico"),
        SecuritySection.DOZE to "Doze"
    )
    val inTools = current in TOOL_SECTIONS
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
        main.forEach { (section, label) -> SectionChip(label, section == current) { onPick(section) } }
        SectionChip(if (english) "Tools" else "Herramientas", inTools) { if (!inTools) onPick(SecuritySection.APK_SCANNER) }
    }
    if (inTools) {
        Spacer(Modifier.height(4.dp))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
            TOOL_SECTIONS.forEach { section -> SectionChip(toolLabels.getValue(section), section == current) { onPick(section) } }
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
    refreshTrigger: Int,
    advancedMode: Boolean = true
) = with(scope) {
    item { ControlPanelCard(context, english, refreshTrigger) }
    // The long technical checklist is only for Advanced mode; Normal mode keeps the control panel above.
    if (advancedMode) item {
        val protection = ProtectionStatus.read(context)
        val ruleStore = remember { RuleStore(context) }
        val listInfo = DomainBlockStore.activeListInfo()
        val threat = ThreatSignatureStore.status(context)
        val threatIntel = ThreatIntelDomainStore.info(context)
        val customRules = CustomDomainRuleStore.snapshot(context)
        val securityAi = runCatching { HydraAiEngine.init(context); HydraAiEngine.isLoaded() }.getOrDefault(false)
        val privacyAi = runCatching { HydraPrivacyAiEngine.init(context); HydraPrivacyAiEngine.isLoaded() }.getOrDefault(false)
        val mh100kAi = runCatching { HydraMh100kApkAi.init(context); HydraMh100kApkAi.isLoaded() }.getOrDefault(false)
        val integrity = AppIntegrity.inspect(context)
        val notificationsEnabled = NotificationManagerCompat.from(context).areNotificationsEnabled()
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
        if (ruleStore.threatProtectionEnabled) StatusRow(english, true, "Amenazas + publicidad", "Threats + ads")
        if (ruleStore.secureDnsEnabled) StatusRow(english, protection.dns, "DNS seguro (${ruleStore.dnsTransport.name})", "Secure DNS (${ruleStore.dnsTransport.name})")
        if (quarantineManager.enabled) StatusRow(english, true, "Cuarentena de apps nuevas", "New-app quarantine")
        if (ruleStore.globalBlockAll) StatusRow(english, true, "Bloquear todo el tráfico", "Block all traffic")
        if (customRules.isNotEmpty()) StatusRow(english, true, "Reglas de dominio personalizadas (${customRules.size})", "Custom domain rules (${customRules.size})")

        Spacer(Modifier.height(10.dp))
        Text(if (english) "OPTIONAL / CURRENTLY OFF" else "OPCIONAL / ACTUALMENTE DESACTIVADO", fontSize = 13.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        if (!ruleStore.threatProtectionEnabled) OptionalStatusRow(english, false, "Amenazas + publicidad", "Threats + ads")
        if (!ruleStore.secureDnsEnabled) OptionalStatusRow(english, false, "DNS seguro", "Secure DNS")
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
            SmallCard(background = MaterialTheme.colorScheme.surfaceVariant) {
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
// Unexpected service stops: a notification already warns about them; this only shows a compact card
// when there is something to look at (it replaces the old "Unexpected stops" page).
// ---------------------------------------------------------------------------
private fun tamperNotice(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    english: Boolean,
    refreshTrigger: Int,
    onChanged: () -> Unit
) = with(scope) {
    val events = ServiceTamperMonitor.eventsSnapshot()
    if (events.isNotEmpty()) item {
        ModernCard {
            Text(
                if (english) "⚠ The protection stopped by itself ${events.size} time(s)" else "⚠ La protección se detuvo sola ${events.size} vez/veces",
                fontWeight = FontWeight.Bold
            )
            Text(
                if (english) "Android or another app closed the VPN without you asking. Hydra restarts it automatically. If it keeps happening, check the battery settings for Hydra."
                else "Android u otra app cerró la VPN sin que lo pidieras. Hydra la reinicia sola. Si se repite, revisá los ajustes de batería de Hydra.",
                fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            events.firstOrNull()?.let { Text(it.time + " • " + it.note, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { ServiceTamperMonitor.clear(); onChanged() }) {
                Text(if (english) "Clear" else "Borrar aviso")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Security history: the antivirus / quarantine / signature events (replaces the old "Timeline" page)
// ---------------------------------------------------------------------------
private fun securityHistory(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        var open by remember { mutableStateOf(false) }
        val events = remember(refreshTrigger, open) { SecurityEventStore.snapshot(context).sortedByDescending { it.time }.take(30) }
        ModernCard {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (english) "Security history (${events.size})" else "Historial de seguridad (${events.size})",
                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
                )
                TextButton(onClick = { open = !open }) { Text(if (open) (if (english) "Hide" else "Ocultar") else (if (english) "Show" else "Ver")) }
            }
            if (open) {
                if (events.isEmpty()) {
                    Text(if (english) "Nothing yet." else "Todavía no hay nada.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    val fmt = java.text.DateFormat.getDateTimeInstance()
                    events.forEach { e ->
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(e.title, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Text(fmt.format(java.util.Date(e.time)) + " • " + e.detail, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
}

/** Rule cleanup lives next to the IP and port rules now (Apps > IP and ports > Cleanup). */
@Composable
fun RuleCleanupPanel(english: Boolean, ipBlockStore: IpBlockStore, advancedRuleStore: AdvancedRuleStore, version: Int, onChanged: () -> Unit) {
    key(version) {
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 4.dp, vertical = 6.dp)) {
            conflictsSection(this, english, ipBlockStore, advancedRuleStore, version, onChanged)
            item { Spacer(Modifier.height(24.dp)) }
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
private data class BulkScanRow(
    val label: String,
    val pkg: String,
    val ai: Int?,
    val riskScore: Int,
    val note: String,
    val seconds: Int = 0,
    val verdict: String = ""
)

/** State of the "scan installed apps" run, kept outside the composable so it survives navigating away. */
private object BulkScanState {
    val running = mutableStateOf(false)
    val done = mutableStateOf(0)
    val total = mutableStateOf(0)
    val current = mutableStateOf("")
    val rows = mutableStateOf<List<BulkScanRow>>(emptyList())
    val cancel = java.util.concurrent.atomic.AtomicBoolean(false)
    val savedAt = mutableStateOf(0L)
    private const val PREFS = "hydra_bulk_scan"

    /** Keep the last results on disk so the list (with each score) is still there after closing the app. */
    fun save(context: Context) {
        runCatching {
            val arr = org.json.JSONArray()
            rows.value.forEach { r ->
                arr.put(org.json.JSONObject().apply {
                    put("label", r.label); put("pkg", r.pkg); put("ai", r.ai ?: -1); put("risk", r.riskScore)
                    put("note", r.note); put("sec", r.seconds); put("verdict", r.verdict)
                })
            }
            val now = System.currentTimeMillis()
            context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("rows", arr.toString()).putLong("at", now).apply()
            savedAt.value = now
        }
    }

    fun restore(context: Context) {
        if (running.value || rows.value.isNotEmpty()) return
        runCatching {
            val p = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val arr = org.json.JSONArray(p.getString("rows", "[]").orEmpty())
            rows.value = (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                BulkScanRow(
                    o.optString("label"), o.optString("pkg"), o.optInt("ai", -1).takeIf { it >= 0 },
                    o.optInt("risk"), o.optString("note"), o.optInt("sec"), o.optString("verdict")
                )
            }
            savedAt.value = p.getLong("at", 0L)
        }
    }
}

private fun apkScannerSection(
    scope: androidx.compose.foundation.lazy.LazyListScope,
    context: Context,
    english: Boolean,
    refreshTrigger: Int
) = with(scope) {
    item {
        var report by remember { mutableStateOf<ApkScanReport?>(null) }
        var scanning by remember { mutableStateOf(false) }
        // The bulk scan lives in a process-wide holder, so leaving this screen and coming back keeps showing the same
        // running scan (progress and results) instead of starting from zero.
        var bulkRunning by BulkScanState.running
        var bulkDone by BulkScanState.done
        var bulkTotal by BulkScanState.total
        var bulkCurrent by BulkScanState.current
        var bulkRows by BulkScanState.rows
        val bulkCancel = BulkScanState.cancel
        val bulkSavedAt by BulkScanState.savedAt
        LaunchedEffect(Unit) { BulkScanState.restore(context) }
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
                if (english) "⚗ Experimental: the score is a guide, not a verdict. It has not been calibrated against enough real apps yet, so a high score does not mean malware and a low one does not mean safe."
                else "⚗ Experimental: el puntaje es orientativo, no un veredicto. Todavía no está calibrado con suficientes apps reales: un puntaje alto no significa malware ni uno bajo significa que es seguro.",
                fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFFFB454)
            )
            Spacer(Modifier.height(6.dp))
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

        Spacer(Modifier.height(8.dp))
        SectionCard {
            Text(if (english) "SCAN ALL INSTALLED APPS" else "ESCANEAR TODAS LAS APPS INSTALADAS", fontWeight = FontWeight.Bold, fontSize = 15.sp)
            Spacer(Modifier.height(4.dp))
            Text(
                if (english) "Scans every app you installed (system apps are skipped) and lists the MH-100K static score of each one. Useful to see how the model behaves on apps you trust: if many legitimate apps score 90 or more, treat the score as unreliable. Everything runs on the phone; results are not saved in the security log and nothing is uploaded. It can take a few minutes."
                else "Escanea todas las apps que instalaste (se omiten las del sistema) y lista el puntaje estático MH-100K de cada una. Sirve para ver cómo se comporta el modelo con apps de confianza: si muchas apps legítimas puntúan 90 o más, tomá el puntaje como poco confiable. Todo corre en el teléfono; los resultados no se guardan en el registro de seguridad y no se sube nada. Puede tardar unos minutos.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Button(
                    enabled = !bulkRunning && !scanning,
                    onClick = {
                        bulkCancel.set(false)
                        bulkRows = emptyList(); bulkDone = 0; bulkTotal = 0; bulkRunning = true
                        val appContext = context.applicationContext
                        Thread {
                            val main = android.os.Handler(android.os.Looper.getMainLooper())
                            val rows = ArrayList<BulkScanRow>()
                            // Each app is scanned on its own worker with a time limit, so one app that
                            // takes too long (or hangs) is reported as "timed out" instead of freezing everything.
                            val exec = java.util.concurrent.Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
                            try {
                                val pm = appContext.packageManager
                                val pkgs = runCatching {
                                    pm.getInstalledApplications(0)
                                        .filter { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 && it.packageName != appContext.packageName }
                                        .map { it.packageName }
                                }.getOrDefault(emptyList())
                                main.post { bulkTotal = pkgs.size }
                                val scanner = ApkScanner(appContext)
                                var timeouts = 0
                                for ((index, pkg) in pkgs.withIndex()) {
                                    if (bulkCancel.get() || timeouts >= 3) break
                                    val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
                                    main.post { bulkCurrent = label }
                                    val startedAt = System.currentTimeMillis()
                                    val future = exec.submit(java.util.concurrent.Callable {
                                        val r = scanner.scanInstalledPackage(pkg)
                                        BulkScanRow(
                                            label, pkg, r.mh100kAi?.score, r.risk.score,
                                            r.errors.firstOrNull { it.startsWith("MH-100K") }.orEmpty(),
                                            ((System.currentTimeMillis() - startedAt) / 1000L).toInt(),
                                            r.mh100kAi?.let { ai ->
                                                HydraMh100kApkAi.verdict(ai.score, ai.apiCallsObserved, ai.dexFilesAnalyzed, ai.extractionIncomplete, false).level.name
                                            }.orEmpty()
                                        )
                                    })
                                    val row = try {
                                        future.get(120, java.util.concurrent.TimeUnit.SECONDS)
                                    } catch (e: java.util.concurrent.TimeoutException) {
                                        future.cancel(true)
                                        timeouts++
                                        BulkScanRow(label, pkg, null, 0, "TIMEOUT 120s", 120)
                                    } catch (e: Throwable) {
                                        BulkScanRow(label, pkg, null, 0, (e.cause ?: e).let { it.message ?: it.javaClass.simpleName })
                                    }
                                    rows.add(row)
                                    val snapshot = rows.toList()
                                    main.post { bulkDone = index + 1; bulkRows = snapshot }
                                }
                            } catch (e: Throwable) {
                                rows.add(BulkScanRow("(error)", "", null, 0, e.message ?: e.javaClass.simpleName))
                                val snapshot = rows.toList()
                                main.post { bulkRows = snapshot }
                            } finally {
                                exec.shutdown()
                                main.post { bulkRunning = false; bulkCurrent = ""; BulkScanState.save(appContext) }
                            }
                        }.start()
                    }
                ) {
                    Text(
                        if (bulkRunning) (if (english) "Scanning $bulkDone/$bulkTotal…" else "Escaneando $bulkDone/$bulkTotal…")
                        else (if (english) "Scan installed apps" else "Escanear apps instaladas")
                    )
                }
                if (bulkRunning) {
                    OutlinedButton(onClick = { bulkCancel.set(true) }) { Text(if (english) "Stop" else "Detener") }
                }
            }
            if (bulkRunning && bulkCurrent.isNotEmpty()) {
                Text(
                    if (english) "Now scanning: $bulkCurrent (120 s limit per app)" else "Escaneando ahora: $bulkCurrent (límite de 120 s por app)",
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (bulkRows.isNotEmpty()) {
                val scored = bulkRows.filter { it.ai != null }
                Spacer(Modifier.height(8.dp))
                if (bulkSavedAt > 0L && !bulkRunning) {
                    Text(
                        (if (english) "Last scan: " else "Último escaneo: ") + java.text.DateFormat.getDateTimeInstance().format(java.util.Date(bulkSavedAt)),
                        fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    if (english) "Scanned ${bulkRows.size} • with score: ${scored.size} • without score: ${bulkRows.size - scored.size}"
                    else "Escaneadas ${bulkRows.size} • con puntaje: ${scored.size} • sin puntaje: ${bulkRows.size - scored.size}",
                    fontWeight = FontWeight.Bold, fontSize = 12.sp
                )
                Text(
                    if (english) "Score 50 or more: ${scored.count { (it.ai ?: 0) >= 50 }} • 90 or more: ${scored.count { (it.ai ?: 0) >= 90 }}"
                    else "Puntaje 50 o más: ${scored.count { (it.ai ?: 0) >= 50 }} • 90 o más: ${scored.count { (it.ai ?: 0) >= 90 }}",
                    fontSize = 12.sp
                )
                Text(
                    if (english) "\"Without score\" means the static analysis was incomplete (large app or time limit), so no score is shown."
                    else "\"Sin puntaje\" significa que el análisis estático quedó incompleto (app grande o límite de tiempo), por eso no se muestra puntaje.",
                    fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                OutlinedButton(onClick = {
                    val header = "# Hydra MH-100K scan | v${com.hydra.firewall.BuildConfig.VERSION_NAME} | " +
                        java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(java.util.Date()) +
                        "\n# score\tlabel\tpackage\tsource\trisk\tseconds\tverdict\tnote\n"
                    val text = header + bulkRows.sortedByDescending { it.ai ?: -1 }
                        .joinToString("\n") { r ->
                            val src = runCatching { AppBehaviorRules.factsFor(context, r.pkg)?.let { AppBehaviorRules.source(it) } }.getOrNull() ?: "unknown"
                            "${r.ai ?: "-"}\t${r.label}\t${r.pkg}\t$src\trisk=${r.riskScore}\t${r.seconds}s\t${r.verdict}\t${r.note}"
                        }
                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("Hydra MH-100K", text))
                }) { Text(if (english) "Copy results" else "Copiar resultados") }
                Spacer(Modifier.height(4.dp))
                bulkRows.sortedByDescending { it.ai ?: -1 }.forEach {
                    Text(
                        "${it.ai?.toString() ?: "—"}  •  ${it.label}  ·  ${it.seconds}s" + (if (it.verdict.isNotEmpty()) "  [${when (it.verdict) { "NORMAL" -> "parece normal"; "DOUBTFUL" -> "dudosa"; "SUSPICIOUS" -> "sospechosa"; else -> "sin conclusión" }}]" else "") + (if (it.ai == null && it.note.isNotBlank()) "  (${it.note.take(70)})" else ""),
                        fontSize = 11.sp,
                        fontWeight = if ((it.ai ?: 0) >= 90) FontWeight.Bold else FontWeight.Normal
                    )
                }
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
                    val verdict = HydraMh100kApkAi.verdict(ai.score, ai.apiCallsObserved, ai.dexFilesAnalyzed, ai.extractionIncomplete, english)
                    Text(
                        (if (english) "Result: " else "Resultado: ") + verdict.label,
                        fontSize = 14.sp, fontWeight = FontWeight.Bold,
                        color = when (verdict.level) {
                            HydraMh100kApkAi.Verdict.Level.NORMAL -> Color(0xFF2E8B57)
                            HydraMh100kApkAi.Verdict.Level.DOUBTFUL -> Color(0xFFD98E1F)
                            HydraMh100kApkAi.Verdict.Level.SUSPICIOUS -> Color(0xFFC0392B)
                            HydraMh100kApkAi.Verdict.Level.INCONCLUSIVE -> MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                    Text(verdict.detail, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        if (english) "Scale: 0–49 looks normal • 50–89 doubtful • 90–100 suspicious (higher = more suspicious)"
                        else "Escala: 0–49 parece normal • 50–89 dudosa • 90–100 sospechosa (más alto = más sospechosa)",
                        fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
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
                SmallCard(background = MaterialTheme.colorScheme.surfaceVariant) {
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
                if (english) "Correlates metadata already collected by Hydra: connections, destinations, DNS blocks, unusual ports. It never changes firewall decisions."
                else "Correlaciona metadatos que Hydra ya recopila: conexiones, destinos, bloqueos DNS, puertos poco habituales. No modifica las decisiones del firewall.",
                fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        HydraAiEngine.init(context)
        HydraPrivacyAiEngine.init(context)
        val behaviors = BehaviorRiskAnalyzer.analyze(TrafficAnalyzerStore.snapshot()).take(30)
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
                        if (english) "unusual ports=${b.unusualPorts} • recent=${b.recentConnections} • new destinations=${b.newDestinations}"
                        else "puertos inusuales=${b.unusualPorts} • recientes=${b.recentConnections} • destinos nuevos=${b.newDestinations}",
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
                        if (b.unusualPorts > 0) add(if (english) "Unusual ports (${b.unusualPorts})" else "Puertos inusuales (${b.unusualPorts})")
                        if (b.recentConnections >= 30) add(if (english) "Recent burst (${b.recentConnections} in 15 min)" else "Pico reciente (${b.recentConnections} en 15 min)")
                        if (b.newDestinations > 0) add(if (english) "New destinations (${b.newDestinations})" else "Destinos nuevos (${b.newDestinations})")
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
