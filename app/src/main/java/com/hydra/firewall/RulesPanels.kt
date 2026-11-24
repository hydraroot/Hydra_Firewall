package com.hydra.firewall

import android.Manifest
import com.hydra.firewall.ui.theme.HydraCard
import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.os.Bundle
import android.os.Process
import android.os.Handler
import android.os.Looper
import android.widget.ImageView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.Canvas
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.hydra.firewall.ui.theme.FirewallLocalTheme
import com.hydra.firewall.security.AppIntegrity
import com.hydra.firewall.security.ProtectionStatus
import com.hydra.firewall.vpn.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.Locale

@Composable
internal fun IpRulesPanel(context: Context, english: Boolean, store: IpBlockStore, version: Int, onChanged: () -> Unit) {
    var input by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf<String?>(null) }
    val rules = remember(version) { store.getBlocked() }
    Column(Modifier.fillMaxSize().padding(top = 10.dp)) {
        Text(if (english) "IP addresses / ranges" else "Direcciones IP / rangos", style = MaterialTheme.typography.titleMedium)
        Text(if (english) "Single IP, CIDR or IPv4 range. Tap a rule for details." else "IP individual, CIDR o rango IPv4. Tocá una regla para ver detalles.", style = MaterialTheme.typography.bodySmall)
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(input, { input = it }, Modifier.weight(1f), singleLine = true, label = { Text("IP / CIDR / rango") })
            Spacer(Modifier.width(8.dp))
            Button({ val v = input.trim(); if (v.isNotEmpty()) { store.add(v); input = ""; onChanged() } }) { Text(tr(context, "add")) }
        }
        Spacer(Modifier.height(8.dp))
        if (rules.isEmpty()) {
            Text(if (english) "No IP rules configured." else "No hay reglas IP configuradas.", style = MaterialTheme.typography.bodySmall)
        } else {
            LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
                items(rules, key = { it }) { rule ->
                    HydraCard(Modifier.fillMaxWidth().padding(vertical = 3.dp).clickable { selected = rule }) {
                        Row(Modifier.fillMaxWidth().padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text("🌐", fontSize = 22.sp, modifier = Modifier.padding(end = 10.dp))
                            Text(rule, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
                            TextButton({ selected = rule }) { Text(if (english) "Details" else "Detalles") }
                        }
                    }
                }
            }
        }
    }
    selected?.let { rule ->
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { selected = null },
            title = { Text(if (english) "IP rule details" else "Detalles de regla IP", color = hydraDialogColors().second) },
            text = { Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(rule, style = MaterialTheme.typography.titleSmall, fontFamily = FontFamily.Monospace)
                Text(if (english) "Action: BLOCK" else "Acción: BLOQUEAR", style = MaterialTheme.typography.bodySmall)
            } },
            dismissButton = { TextButton({ store.remove(rule); onChanged(); selected = null }) { Text(if (english) "Delete rule" else "Eliminar regla") } },
            confirmButton = { TextButton({ selected = null }) { Text(tr(context, "close")) } }
        )
    }
}

@Composable
internal fun PortRulesPanel(
    context: Context,
    english: Boolean,
    apps: List<AppEntry>,
    store: AdvancedRuleStore,
    version: Int,
    onChanged: () -> Unit
) {
    var scopeGlobal by remember { mutableStateOf(true) }
    var selectedUid by remember { mutableStateOf<Int?>(null) }
    var protocol by remember { mutableStateOf("TCP") }
    var portText by remember { mutableStateOf("") }
    var allow by remember { mutableStateOf(false) }
    var appMenuExpanded by remember { mutableStateOf(false) }
    var selectedRule by remember { mutableStateOf<AdvancedRuleStore.Rule?>(null) }
    val rules = remember(version, scopeGlobal, selectedUid) {
        store.getAll().filter { rule ->
            if (scopeGlobal) rule.uid == AdvancedRuleStore.GLOBAL_UID
            else selectedUid != null && rule.uid == selectedUid
        }
    }

    fun clearCurrentScope() {
        if (scopeGlobal) {
            store.getAll()
                .filter { it.uid == AdvancedRuleStore.GLOBAL_UID }
                .forEach(store::remove)
        } else {
            selectedUid?.let(store::clearForUid)
        }
        selectedRule = null
        onChanged()
    }

    Column(Modifier.fillMaxSize().padding(top = 10.dp)) {
        Text(
            if (english) "Ports / port ranges" else "Puertos / rangos de puertos",
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            if (english) "Choose Global for all apps or Application for one app."
            else "Elegí Global para todas las aplicaciones o Aplicación para una sola.",
            style = MaterialTheme.typography.bodySmall
        )

        Spacer(Modifier.height(8.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            HydraChoiceButton(scopeGlobal, "GLOBAL", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = { scopeGlobal = true; selectedUid = null }, modifier = Modifier.height(30.dp))
            HydraChoiceButton(!scopeGlobal, if (english) "APPLICATION" else "APLICACIÓN", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = { scopeGlobal = false }, modifier = Modifier.height(30.dp))
            Spacer(Modifier.weight(1f))
            OutlinedButton(
                onClick = { clearCurrentScope() },
                enabled = rules.isNotEmpty() || (!scopeGlobal && selectedUid != null),
            ) {
                Text(if (english) "CLEAR" else "LIMPIAR")
            }
        }

        if (!scopeGlobal) {
            Spacer(Modifier.height(8.dp))
            Box(Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { appMenuExpanded = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    val label = apps.firstOrNull { it.uid == selectedUid }?.label
                        ?: if (english) "Choose application" else "Elegir aplicación"
                    Text(label, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                }
                DropdownMenu(
                    expanded = appMenuExpanded,
                    onDismissRequest = { appMenuExpanded = false }
                ) {
                    apps.forEach { app ->
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    AppIcon(app, Modifier.size(30.dp).padding(end = 6.dp))
                                    Column {
                                        Text(app.label)
                                        if (app.isSystem) {
                                            Text(
                                                "SISTEMA",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.error
                                            )
                                        }
                                    }
                                }
                            },
                            onClick = {
                                selectedUid = app.uid
                                appMenuExpanded = false
                            }
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            HydraChoiceButton(protocol == "TCP", "TCP", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = { protocol = "TCP" }, modifier=Modifier.height(30.dp))
            Spacer(Modifier.width(4.dp))
            HydraChoiceButton(protocol == "UDP", "UDP", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = { protocol = "UDP" }, modifier=Modifier.height(30.dp))
            Spacer(Modifier.width(8.dp))
            HydraChoiceButton(allow, if (allow) (if (english) "ALLOW" else "PERMITIR") else (if (english) "BLOCK" else "BLOQUEAR"), if (allow) Color(0xFFD5F5E3) else Color(0xFFF1D0D0), if (allow) Color(0xFF145A32) else Color(0xFF7A1E1E), onClick = { allow = !allow }, modifier=Modifier.height(30.dp))
        }

        Spacer(Modifier.height(6.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text(if (english) "Port or range" else "Puerto o rango") },
                placeholder = { Text("443   ó   8000-8080") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
            )
            Spacer(Modifier.width(6.dp))
            Button(
                onClick = {
                    val uid = if (scopeGlobal) AdvancedRuleStore.GLOBAL_UID else selectedUid
                    val parts = portText.trim().split('-')
                    val start = parts.getOrNull(0)?.trim()?.toIntOrNull()
                    val end = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: start
                    if (uid != null && start != null && end != null && start in 1..65535 && end in start..65535) {
                        store.set(uid, protocol, start, end, allow)
                        portText = ""
                        onChanged()
                    }
                },
                enabled = scopeGlobal || selectedUid != null
            ) {
                Text(tr(context, "add"))
            }
        }

        Spacer(Modifier.height(10.dp))
        Text(
            if (scopeGlobal) {
                if (english) "Global rules (${rules.size})" else "Reglas globales (${rules.size})"
            } else {
                val label = apps.firstOrNull { it.uid == selectedUid }?.label
                    ?: if (english) "Application rules" else "Reglas de aplicación"
                "$label (${rules.size})"
            },
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(Modifier.height(4.dp))

        if (!scopeGlobal && selectedUid == null) {
            Text(
                if (english) "Choose an application to view and manage its port rules."
                else "Elegí una aplicación para ver y administrar sus reglas de puertos.",
                style = MaterialTheme.typography.bodySmall
            )
        } else if (rules.isEmpty()) {
            Text(
                if (english) "No port rules configured in this scope."
                else "No hay reglas de puertos configuradas en este ámbito.",
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            LazyColumn(
                Modifier.fillMaxWidth().weight(1f)
            ) {
                items(
                    rules,
                    key = { "${it.uid}:${it.protocol}:${it.startPort}:${it.endPort}:${it.allowed}" }
                ) { rule ->
                    val app = apps.firstOrNull { it.uid == rule.uid }
                    val appLabel = if (rule.uid == AdvancedRuleStore.GLOBAL_UID) {
                        if (english) "GLOBAL — ALL APPS" else "GLOBAL — TODAS LAS APPS"
                    } else {
                        app?.label ?: com.hydra.firewall.vpn.AppNames.label(rule.uid)
                    }
                    HydraCard(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 3.dp)
                            .clickable { selectedRule = rule }
                    ) {
                        Row(
                            Modifier.fillMaxWidth().padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            if (rule.uid == AdvancedRuleStore.GLOBAL_UID) {
                                Surface(
                                    modifier = Modifier.size(44.dp),
                                    shape = MaterialTheme.shapes.medium,
                                    color = MaterialTheme.colorScheme.secondaryContainer
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Text("G", style = MaterialTheme.typography.titleMedium)
                                    }
                                }
                            } else {
                                AppIcon(app, Modifier.size(44.dp).padding(end = 8.dp))
                            }
                            Spacer(Modifier.width(8.dp))
                            Column(Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        appLabel,
                                        style = MaterialTheme.typography.titleMedium,
                                        maxLines = 1,
                                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                                    )
                                    if (app?.isSystem == true) {
                                        Spacer(Modifier.width(6.dp))
                                        Surface(
                                            shape = MaterialTheme.shapes.small,
                                            color = MaterialTheme.colorScheme.errorContainer
                                        ) {
                                            Text(
                                                "SISTEMA",
                                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onErrorContainer
                                            )
                                        }
                                    }
                                }
                                Text(
                                    "${rule.protocol} ${rule.startPort}${if (rule.endPort != rule.startPort) "-${rule.endPort}" else ""}",
                                    fontFamily = FontFamily.Monospace,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    if (rule.allowed) (if (english) "ALLOW" else "PERMITIR") else (if (english) "BLOCK" else "BLOQUEAR"),
                                    style = MaterialTheme.typography.labelLarge
                                )
                            }
                            TextButton({ selectedRule = rule }) {
                                Text(if (english) "Details" else "Detalles")
                            }
                        }
                    }
                }
            }
        }
    }

    selectedRule?.let { rule ->
        val app = apps.firstOrNull { it.uid == rule.uid }
        val appLabel = if (rule.uid == AdvancedRuleStore.GLOBAL_UID) {
            if (english) "GLOBAL — ALL APPS" else "GLOBAL — TODAS LAS APPS"
        } else {
            app?.label ?: com.hydra.firewall.vpn.AppNames.label(rule.uid)
        }
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { selectedRule = null },
            title = { Text(if (english) "Port rule details" else "Detalles de regla de puerto", color = hydraDialogColors().second) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(appLabel, style = MaterialTheme.typography.titleMedium)
                    Text("${rule.protocol} • ${rule.startPort}${if (rule.endPort != rule.startPort) "-${rule.endPort}" else ""}", fontFamily = FontFamily.Monospace)
                    Text(if (rule.allowed) (if (english) "Action: ALLOW" else "Acción: PERMITIR") else (if (english) "Action: BLOCK" else "Acción: BLOQUEAR"))
                }
            },
            dismissButton = {
                TextButton({
                    store.remove(rule)
                    onChanged()
                    selectedRule = null
                }) { Text(if (english) "Delete rule" else "Eliminar regla") }
            },
            confirmButton = {
                TextButton({ selectedRule = null }) { Text(tr(context, "close")) }
            }
        )
    }
}

@Composable
internal fun AdvancedRulesEditor(context: Context, apps: List<AppEntry>, store: AdvancedRuleStore, version: Int, onChanged: () -> Unit, english: Boolean) {
    var selectedUid by remember { mutableStateOf<Int?>(null) }
    var protocol by remember { mutableStateOf("TCP") }
    var portText by remember { mutableStateOf("443") }
    var allow by remember { mutableStateOf(false) }
    var selectedRule by remember { mutableStateOf<AdvancedRuleStore.Rule?>(null) }
    val rules = remember(version) { store.getAll() }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        var expanded by remember { mutableStateOf(false) }
        Box { TextButton({ expanded = true }) { Text(apps.firstOrNull { it.uid == selectedUid }?.label ?: if(english) "Choose app" else "Elegir app") }; DropdownMenu(expanded, { expanded=false }) { apps.take(80).forEach { a -> DropdownMenuItem(text={Text(a.label)}, onClick={selectedUid=a.uid; expanded=false}) } } }
        Spacer(Modifier.width(4.dp)); HydraChoiceButton(protocol == "TCP", "TCP", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick={ protocol="TCP" }, modifier=Modifier.height(30.dp)); Spacer(Modifier.width(4.dp)); HydraChoiceButton(protocol == "UDP", "UDP", MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick={ protocol="UDP" }, modifier=Modifier.height(30.dp))
    }
    Row(Modifier.fillMaxWidth(), verticalAlignment=Alignment.CenterVertically) {
        OutlinedTextField(portText,{portText=it},Modifier.weight(1f),singleLine=true,label={Text(if(english) "Port or range (443 or 8000-8080)" else "Puerto o rango (443 o 8000-8080)")})
        Spacer(Modifier.width(6.dp)); HydraChoiceButton(allow, if(allow) (if(english)"Allow" else "Permitir") else (if(english)"Block" else "Bloquear"), if (allow) Color(0xFFD5F5E3) else Color(0xFFF1D0D0), if (allow) Color(0xFF145A32) else Color(0xFF7A1E1E), onClick={allow=!allow}, modifier=Modifier.height(30.dp))
        Spacer(Modifier.width(6.dp)); Button({ val uid=selectedUid; val parts=portText.trim().split('-'); val a=parts.firstOrNull()?.toIntOrNull(); val b=(if(parts.size>1)parts[1].toIntOrNull() else a); if(uid!=null&&a!=null&&b!=null&&a in 0..65535&&b in a..65535){store.set(uid,protocol,a,b,allow); onChanged()} }) { Text(tr(context,"add")) }
    }
    Spacer(Modifier.height(8.dp))
    Text(if (english) "Configured port rules" else "Reglas de puertos configuradas", style = MaterialTheme.typography.titleSmall)
    if (rules.isEmpty()) {
        Text(if (english) "No configured port rules." else "No hay reglas de puertos configuradas.", style = MaterialTheme.typography.bodySmall)
    } else {
        rules.forEach { r ->
            key(r.uid, r.protocol, r.startPort, r.endPort, r.allowed) {
                val appLabel = apps.firstOrNull { it.uid == r.uid }?.label ?: com.hydra.firewall.vpn.AppNames.label(r.uid)
                HydraCard(Modifier.fillMaxWidth().padding(vertical = 3.dp).clickable { selectedRule = r }) {
                    Row(Modifier.fillMaxWidth().padding(9.dp),verticalAlignment=Alignment.CenterVertically){
                        AppIcon(apps.firstOrNull { it.uid == r.uid }, Modifier.size(40.dp).padding(end = 8.dp))
                        Column(Modifier.weight(1f)){
                            Text(appLabel, style=MaterialTheme.typography.titleSmall)
                            Text("${r.protocol} ${r.startPort}${if(r.endPort!=r.startPort)"-${r.endPort}" else ""}",fontFamily=FontFamily.Monospace,fontSize=11.sp)
                            Text(if(r.allowed)(if(english)"ALLOW" else "PERMITIR") else (if(english)"BLOCK" else "BLOQUEAR"),style=MaterialTheme.typography.bodySmall)
                        }
                        TextButton({selectedRule=r}){Text(if(english)"Details" else "Detalles")}
                    }
                }
            }
        }
    }
    selectedRule?.let { rule ->
        val appLabel = apps.firstOrNull { it.uid == rule.uid }?.label ?: com.hydra.firewall.vpn.AppNames.label(rule.uid)
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { selectedRule = null },
            title = { Text(if(english) "Port rule details" else "Detalles de regla de puerto") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(appLabel, style=MaterialTheme.typography.titleSmall)
                Text("UID ${rule.uid}", style=MaterialTheme.typography.bodySmall)
                Text("${rule.protocol} • ${rule.startPort}${if(rule.endPort!=rule.startPort)"-${rule.endPort}" else ""}", fontFamily=FontFamily.Monospace)
                Text(if(rule.allowed)(if(english)"Action: ALLOW" else "Acción: PERMITIR") else (if(english)"Action: BLOCK" else "Acción: BLOQUEAR"))
            } },
            dismissButton = { TextButton({ store.remove(rule); onChanged(); selectedRule=null }) { Text(if(english) "Delete rule" else "Eliminar regla") } },
            confirmButton = { TextButton({ selectedRule = null }) { Text(tr(context,"close")) } }
        )
    }
}

@Composable
internal fun AllowBlockRow(
    label: String,
    allowed: Boolean,
    info: String,
    promptInfo: String,
    onChanged: (Boolean)->Unit
) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)).padding(12.dp)
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(info, style = MaterialTheme.typography.bodySmall)
        Text(promptInfo, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(4.dp))
        Box(Modifier.fillMaxWidth().height(40.dp)) {
            val scrollState = rememberScrollState()
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(scrollState)
                    .padding(horizontal = 22.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                HydraChoiceButton(
                    selected = allowed,
                    label = (if (AppSettings(LocalContext.current).language.isEnglish()) "Allow by default" else "Permitir por defecto").let { if (allowed) "✓ $it" else it },
                    selectedColor = Color(0xFF00796B),
                    selectedLabelColor = Color.White,
                    onClick = { onChanged(true) },
                    fontSize = 11.sp
                )
                HydraChoiceButton(
                    selected = !allowed,
                    label = (if (AppSettings(LocalContext.current).language.isEnglish()) "Block by default" else "Bloquear por defecto").let { if (!allowed) "✓ $it" else it },
                    selectedColor = Color(0xFFC62828),
                    selectedLabelColor = Color.White,
                    onClick = { onChanged(false) },
                    fontSize = 11.sp
                )
            }
            val darkMode = MaterialTheme.colorScheme.background.luminance() < 0.5f
            if (scrollState.maxValue > 0 && scrollState.value > 0) {
                Text("◀", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                    modifier = Modifier.align(Alignment.CenterStart)
                        .background(MaterialTheme.colorScheme.surface.copy(alpha = if (darkMode) 0.82f else 0.92f), RoundedCornerShape(8.dp))
                        .padding(horizontal = 5.dp, vertical = 2.dp))
            }
            if (scrollState.maxValue > 0 && scrollState.value < scrollState.maxValue) {
                Text("▶", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                    modifier = Modifier.align(Alignment.CenterEnd)
                        .background(MaterialTheme.colorScheme.surface.copy(alpha = if (darkMode) 0.82f else 0.92f), RoundedCornerShape(8.dp))
                        .padding(horizontal = 5.dp, vertical = 2.dp))
            }
        }
    }
}

@Composable
internal fun DomainRulesPanel(
    context: Context,
    english: Boolean,
    version: Int,
    onChanged: () -> Unit
) {
    var input by remember(version) { mutableStateOf("") }
    var rules by remember(version) { mutableStateOf(CustomDomainRuleStore.snapshot(context)) }
    var message by remember(version) { mutableStateOf<String?>(null) }

    fun refresh() {
        rules = CustomDomainRuleStore.snapshot(context)
        onChanged()
    }

    Column(Modifier.fillMaxSize()) {
        Text(
            if (english) "Custom domain protection" else "Protección de dominios personalizada",
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            if (english)
                "BLOCK overrides normal blocklists. ALLOW overrides ads/trackers, but confirmed threat signatures still win."
            else
                "BLOQUEAR tiene prioridad sobre las listas normales. PERMITIR anula anuncios/trackers, pero una amenaza confirmada siempre sigue bloqueada.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
        )
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text(if (english) "Domain" else "Dominio") },
            placeholder = { Text("ads.example.com") }
        )
        HydraHorizontalRow(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Button(onClick = {
                if (CustomDomainRuleStore.set(context, input, CustomDomainRuleStore.Action.BLOCK)) {
                    input = ""
                    message = null
                    refresh()
                } else {
                    message = if (english) "Enter a valid domain." else "Ingresá un dominio válido."
                }
            }) { Text(if (english) "BLOCK" else "BLOQUEAR") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = {
                if (CustomDomainRuleStore.set(context, input, CustomDomainRuleStore.Action.ALLOW)) {
                    input = ""
                    message = null
                    refresh()
                } else {
                    message = if (english) "Enter a valid domain." else "Ingresá un dominio válido."
                }
            }) { Text(if (english) "ALLOW" else "PERMITIR") }
        }
        message?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(4.dp))
        if (rules.isEmpty()) {
            Text(
                if (english) "No custom domain rules." else "No hay reglas de dominio personalizadas.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            LazyColumn(Modifier.weight(1f)) {
                items(rules, key = { "${it.domain}:${it.action}" }) { rule ->
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 7.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(rule.domain, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                            Text(
                                if (rule.action == CustomDomainRuleStore.Action.BLOCK)
                                    if (english) "BLOCK" else "BLOQUEAR"
                                else if (english) "ALLOW" else "PERMITIR",
                                color = if (rule.action == CustomDomainRuleStore.Action.BLOCK) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp
                            )
                        }
                        TextButton(onClick = { CustomDomainRuleStore.remove(context, rule.domain); refresh() }) {
                            Text(if (english) "Delete" else "Eliminar")
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
internal fun AppRuleRow(
    app: AppEntry,
    wifiAllowed: Boolean,
    mobileAllowed: Boolean,
    explicitRule: Boolean,
    autoEssential: Boolean,
    userEssential: Boolean,
    customized: Boolean,
    compatibilityExcluded: Boolean,
    scheduleEnabled: Boolean,
    favorite: Boolean,
    onWifiChanged: (Boolean) -> Unit,
    onMobileChanged: (Boolean) -> Unit,
    onRemoveEssential: () -> Unit,
    onMakeEssential: () -> Unit,
    onFavorite: () -> Unit,
    onCustom: () -> Unit,
    onDetails: () -> Unit,
    onSchedule: () -> Unit,
    onCompatibility: () -> Unit,
    extra: @Composable () -> Unit = {}
) {
    val context = LocalContext.current
    val en = AppSettings(context).language.isEnglish()
    val policyColor = appRulePolicyColor(compatibilityExcluded, wifiAllowed, mobileAllowed)
    var expanded by remember { mutableStateOf(false) }
    val currentMode = AppCompatibilityPolicyStore.getMode(app.packageName)
    val ruleMode = when {
        compatibilityExcluded -> AppCompatibilityMode.EXCLUDED
        customized -> AppCompatibilityMode.CUSTOM
        userEssential -> AppCompatibilityMode.ESSENTIAL
        else -> AppCompatibilityMode.NORMAL
    }
    // One short line under the app name (the long explanation is still shown in the toast when a switch changes).
    val statusLine = when (ruleMode) {
        AppCompatibilityMode.CUSTOM -> if (en) "Custom · protections" else "Personalizado · protecciones"
        AppCompatibilityMode.EXCLUDED -> if (en) "No firewall · outside Hydra" else "Sin firewall · fuera de Hydra"
        AppCompatibilityMode.ESSENTIAL -> if (en) "Permissive · flexible filters" else "Permisivo · filtros flexibles"
        else -> when {
            wifiAllowed && mobileAllowed -> if (en) "Allowed · Wi‑Fi and mobile" else "Permitida · Wi‑Fi y datos"
            wifiAllowed -> if (en) "Wi‑Fi only · mobile blocked" else "Solo Wi‑Fi · datos bloqueados"
            mobileAllowed -> if (en) "Mobile only · Wi‑Fi blocked" else "Solo datos · Wi‑Fi bloqueado"
            explicitRule -> if (en) "Blocked · Wi‑Fi and mobile" else "Bloqueada · Wi‑Fi y datos"
            else -> if (en) "Blocked · will ask on next connection" else "Bloqueada · preguntará al conectar"
        }
    }
    HydraCard(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(36.dp)) {
                    AppIcon(app, Modifier.size(36.dp))
                    Box(
                        Modifier.align(Alignment.BottomEnd).size(11.dp).clip(CircleShape)
                            .background(MaterialTheme.colorScheme.surface).padding(2.dp).clip(CircleShape).background(policyColor)
                    )
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f).padding(end = 6.dp)) {
                    Text(app.label, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                    Text(statusLine, fontSize = 10.5.sp, color = policyColor, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                    if (app.members.size > 1) Text(
                        if (en) "${app.members.size} apps share this rule" else "${app.members.size} apps comparten esta regla",
                        fontSize = 9.5.sp, color = MaterialTheme.colorScheme.tertiary, maxLines = 1
                    )
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Switch(checked = wifiAllowed, enabled = !compatibilityExcluded, onCheckedChange = onWifiChanged, modifier = Modifier.height(24.dp).scale(0.78f))
                    Text(tr(context, "wifi"), fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.width(4.dp))
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Switch(checked = mobileAllowed, enabled = !compatibilityExcluded, onCheckedChange = onMobileChanged, modifier = Modifier.height(24.dp).scale(0.78f))
                    Text(if (en) "Data" else "Datos", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (expanded) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider()
                Spacer(Modifier.height(10.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    RuleModePill(Modifier.weight(1f), if (en) "Custom" else "Personalizado", customized, policyColor, onCustom)
                    RuleModePill(Modifier.weight(1f), if (en) "Permissive" else "Permisivo", userEssential, policyColor, if (userEssential) onRemoveEssential else onMakeEssential)
                    RuleModePill(Modifier.weight(1f), if (en) "No firewall" else "Sin firewall", compatibilityExcluded, Color(0xFF3B82C4), onCompatibility)
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "${app.packageName} · UID ${app.uid}",
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 9.5.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
                if (app.members.size > 1) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        if (en) "APPS THAT SHARE THIS RULE" else "APPS QUE COMPARTEN ESTA REGLA",
                        fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        if (en) "Android treats them as one app, so Wi‑Fi, data, mode and schedule apply to all of them together."
                        else "Android las trata como una sola, así que Wi‑Fi, datos, modo y horario valen para todas juntas.",
                        fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    app.members.take(12).forEach { m ->
                        Text(
                            "• ${m.label}  ${m.packageName}",
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 9.5.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                        )
                    }
                    if (app.members.size > 12) Text("+ ${app.members.size - 12}", fontSize = 9.5.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (app.isSystem) Text(tr(context, "system").uppercase(), fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(6.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    RuleModePill(Modifier.weight(1f), if (en) "Details" else "Detalles", false, policyColor, onDetails)
                    RuleModePill(Modifier.weight(1f), if (scheduleEnabled) tr(context, "schedule_short_active") else tr(context, "schedule_short"), scheduleEnabled, policyColor, onSchedule)
                    RuleModePill(Modifier.weight(1f), if (favorite) "★" else "☆", favorite, Color(0xFF8A44B8), onFavorite)
                }
                extra()
            }
        }
    }
}
