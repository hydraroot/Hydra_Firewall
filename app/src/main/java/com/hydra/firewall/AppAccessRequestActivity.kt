package com.hydra.firewall

import android.os.Bundle
import android.widget.ImageView
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.hydra.firewall.ui.theme.FirewallLocalTheme
import com.hydra.firewall.vpn.ConnectionContext
import com.hydra.firewall.vpn.CustomProtectionProfileStore
import com.hydra.firewall.vpn.DecisionRequestManager
import com.hydra.firewall.vpn.EssentialAppsStore
import com.hydra.firewall.vpn.NetworkKind
import com.hydra.firewall.vpn.RuleStore

class AppAccessRequestActivity : ComponentActivity() {
    companion object {
        const val EXTRA_TOKEN = "decision_token"
        private val live = HashMap<String, java.lang.ref.WeakReference<AppAccessRequestActivity>>()

        /**
         * Intent único por solicitud. Android considera iguales dos intents con el mismo componente
         * aunque cambien los extras; por eso, con varias solicitudes acumuladas en las notificaciones,
         * tocar una podía traer al frente otra o no abrir nada. El `data` distinto por token y
         * MULTIPLE_TASK hacen que cada solicitud tenga su propia ventana.
         */
        fun buildIntent(context: android.content.Context, token: String): android.content.Intent =
            android.content.Intent(context, AppAccessRequestActivity::class.java).apply {
                data = android.net.Uri.parse("hydra-access://request/$token")
                // NEW_DOCUMENT sin MULTIPLE_TASK: una tarea por `data` (= por solicitud). Relanzar la misma
                // solicitud trae al frente su ventana existente en vez de apilar otra copia.
                addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_NEW_DOCUMENT)
                putExtra(EXTRA_TOKEN, token)
            }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val token = intent.getStringExtra(EXTRA_TOKEN)
        val request = token?.let { DecisionRequestManager.get(it) }
        if (request == null) {
            // Solicitud ya resuelta (o el servicio se reinició): limpiar su notificación y avisar,
            // en vez de cerrar en silencio como si la notificación "no abriera".
            token?.let { com.hydra.firewall.vpn.NotificationHelper.clearAccessRequestNotification(applicationContext, it) }
            android.widget.Toast.makeText(
                this,
                if (AppSettings(applicationContext).language == AppLanguage.EN) "This request was already resolved." else "Esta solicitud ya fue resuelta.",
                android.widget.Toast.LENGTH_SHORT
            ).show()
            finish()
            return
        }

        // Protección extra contra copias duplicadas del mismo aviso: si ya hay una ventana viva para
        // este token, esta copia se cierra y queda la original.
        val me = token!!
        val alreadyShown = synchronized(live) {
            val prev = live[me]?.get()
            if (prev != null && prev !== this && !prev.isFinishing && !prev.isDestroyed) true
            else { live[me] = java.lang.ref.WeakReference(this); false }
        }
        if (alreadyShown) { finish(); return }
        DecisionRequestManager.onPromptShown(me)

        val storedTheme = settingsTheme(applicationContext)
        setContent {
            val darkTheme = when (storedTheme) {
                ThemeMode.DARK -> true
                ThemeMode.LIGHT -> false
                ThemeMode.SYSTEM -> androidx.compose.foundation.isSystemInDarkTheme()
            }
            FirewallLocalTheme(darkTheme = darkTheme) {
                AppAccessRequestScreen(
                    packageName = request.packageName ?: if (AppSettings(applicationContext).language == AppLanguage.EN) "Unknown application" else "Aplicación desconocida",
                    uid = request.uid,
                    protocolLabel = request.protocolLabel,
                    destination = formatEndpoint(request.key.dstAddr, request.key.dstPort),
                    triggeringNetwork = request.network.displayName,
                    initialWifi = request.initialWifiAllowed,
                    initialMobile = request.initialMobileAllowed,
                    token = token,
                    onDecision = { wifi, mobile, persistence ->
                        token?.let { DecisionRequestManager.resolve(it, wifi, mobile, persistence) }
                        finish()
                    },
                    onCustomDecision = { wifi, mobile, profile ->
                        token?.let { DecisionRequestManager.resolveCustom(it, wifi, mobile, profile) }
                        finish()
                    },
                    onNoFirewall = {
                        token?.let { DecisionRequestManager.resolveNoFirewall(it) }
                        finish()
                    },
                    onCancel = {
                        // BLOCK is a persistent explicit deny for both networks.
                        token?.let {
                            DecisionRequestManager.resolve(
                                it,
                                false,
                                false,
                                DecisionRequestManager.Persistence.ALWAYS
                            )
                        }
                        finish()
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Si la solicitud ya fue resuelta (p. ej. desde otra copia o desde la notificación), esta
        // ventana quedó obsoleta: cerrarla para que no aparezca "el mismo aviso" otra vez.
        val t = intent.getStringExtra(EXTRA_TOKEN)
        if (t != null && DecisionRequestManager.get(t) == null) finish()
        else if (t != null) DecisionRequestManager.onPromptShown(t)
    }

    override fun onDestroy() {
        val t = intent.getStringExtra(EXTRA_TOKEN)
        if (t != null) synchronized(live) { if (live[t]?.get() === this) live.remove(t) }
        if (t != null && isFinishing && DecisionRequestManager.get(t) != null) {
            DecisionRequestManager.onPromptClosedWithoutDecision(t)
        }
        super.onDestroy()
    }
}

@Composable
private fun AppAccessRequestScreen(
    packageName: String,
    uid: Int,
    protocolLabel: String,
    destination: String,
    triggeringNetwork: String,
    initialWifi: Boolean,
    initialMobile: Boolean,
    token: String?,
    onDecision: (Boolean, Boolean, DecisionRequestManager.Persistence) -> Unit,
    onCustomDecision: (Boolean, Boolean, CustomProtectionProfileStore.Profile) -> Unit,
    onNoFirewall: () -> Unit,
    onCancel: () -> Unit
) {
    val context = LocalContext.current
    val english = remember { AppSettings(context).language == AppLanguage.EN }

    // For a first prompt with no saved rule, enable the network that actually
    // triggered the request. The user can then enable/disable the other one.
    // Por defecto, en un primer aviso (app sin regla propia) los dos interruptores arrancan activos;
    // el usuario puede apagar el que no quiera. Si ya había una regla explícita se respeta lo guardado.
    val hasExplicit = remember(uid) { runCatching { RuleStore(context).hasExplicitRule(uid) }.getOrDefault(false) }
    var wifi by remember(initialWifi, triggeringNetwork) {
        mutableStateOf(if (hasExplicit) initialWifi else true)
    }
    var mobile by remember(initialMobile, triggeringNetwork) {
        mutableStateOf(if (hasExplicit) initialMobile else true)
    }

    var groupedAttempts by remember { mutableStateOf<List<DecisionRequestManager.Attempt>>(emptyList()) }
    var showDetails by remember { mutableStateOf(false) }
    var showCustom by remember { mutableStateOf(false) }
    var customProfile by remember { mutableStateOf(CustomProtectionProfileStore.defaults()) }

    LaunchedEffect(token) {
        while (true) {
            groupedAttempts = token?.let {
                DecisionRequestManager.get(it)?.attempts?.toList().orEmpty()
            }.orEmpty()
            kotlinx.coroutines.delay(350L)
        }
    }

    val uidPackages = remember(uid) { loadUidPackages(context, uid) }
    val resolvedPackage = remember(packageName, uidPackages) {
        packageName.takeIf { it.isNotBlank() } ?: uidPackages.firstOrNull()?.packageName
    }
    val resolvedApp = remember(resolvedPackage, uid) {
        val pm = context.packageManager
        val direct = resolvedPackage?.let { runCatching { pm.getApplicationInfo(it, 0) }.getOrNull() }
        direct ?: uidPackages.firstOrNull()?.packageName?.let {
            runCatching { pm.getApplicationInfo(it, 0) }.getOrNull()
        }
    }
    val label = remember(resolvedPackage, uid, uidPackages) {
        val pm = context.packageManager
        runCatching { resolvedApp?.let { pm.getApplicationLabel(it).toString() } }
            .getOrNull()?.takeIf { it.isNotBlank() }
            ?: uidPackages.firstOrNull()?.label?.takeIf { it.isNotBlank() }
            ?: packageName.takeIf { it.isNotBlank() }
            ?: (if (english) "Unknown application" else "Aplicación desconocida")
    }
    val iconAvailable = remember(resolvedPackage, uid, uidPackages) {
        resolvedApp?.let { runCatching { context.packageManager.getApplicationIcon(it) }.getOrNull() }
            ?: uidPackages.firstOrNull()?.icon
    }
    val uidPermissionPackages = remember(uid) { loadUidPermissionGroups(context, uid) }
    val permissionGroups = remember(packageName) { loadAppPermissionGroups(context, packageName) }
    val runningProcesses = remember(uid) { loadRunningProcesses(context, uid) }

    // La pantalla debe poder desplazarse siempre que el contenido pueda superar la altura de la ventana:
    // con "Personalizado" abierto hay 7 interruptores y, sin scroll, Compose los aplastaba (se superponían).
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .padding(16.dp)
            .then(if (showDetails || showCustom) Modifier.verticalScroll(scrollState) else Modifier),
        verticalArrangement = Arrangement.Center
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    AndroidView(
                        modifier = Modifier.size(52.dp),
                        factory = { ImageView(it).apply {
                            scaleType = ImageView.ScaleType.CENTER_INSIDE
                            contentDescription = label
                        } },
                        update = { view ->
                            view.contentDescription = label
                            view.setImageDrawable(iconAvailable)
                        }
                    )
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.Center) {
                        Text(
                            label,
                            style = MaterialTheme.typography.titleLarge,
                            maxLines = 2,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                        )
                    }
                }

                Spacer(Modifier.size(10.dp))

                // Four clear actions. The descriptions remain simple so the
                // user can choose without opening Details.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp)
                ) {
                    PromptAction(
                        buttonText = if (english) "ALLOW" else "PERMITIR",
                        description = if (english) "Normal HYDRA protection and filtering." else "Protección y filtros normales de HYDRA.",
                        modifier = Modifier.weight(1f),
                        onClick = { onDecision(wifi, mobile, DecisionRequestManager.Persistence.ALWAYS) }
                    )
                    PromptAction(
                        buttonText = if (english) "PERMISSIVE" else "PERMISIVO",
                        description = if (english) "Goes through HYDRA with more compatibility." else "Pasa por HYDRA con más compatibilidad.",
                        modifier = Modifier.weight(1f),
                        onClick = { onDecision(wifi, mobile, DecisionRequestManager.Persistence.ESSENTIAL) }
                    )
                }
                Spacer(Modifier.size(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp)
                ) {
                    PromptAction(
                        buttonText = if (english) "NO FIREWALL" else "SIN FIREWALL",
                        description = if (english) "Uses Android's normal network, outside HYDRA." else "Usa la red normal, fuera de HYDRA.",
                        modifier = Modifier.weight(1f),
                        onClick = {
                            wifi = false
                            mobile = false
                            onNoFirewall()
                        }
                    )
                    PromptAction(
                        buttonText = if (english) "BLOCK" else "BLOQUEAR",
                        description = if (english) "Blocks network access for this app." else "Bloquea el acceso de red de esta app.",
                        modifier = Modifier.weight(1f),
                        onClick = {
                            wifi = false
                            mobile = false
                            onCancel()
                        }
                    )
                }

                Spacer(Modifier.size(7.dp))
                OutlinedButton(
                    onClick = { showCustom = !showCustom },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (showCustom) {
                        if (english) "PERSONALIZED ▲" else "PERSONALIZADO ▲"
                    } else {
                        if (english) "PERSONALIZED" else "PERSONALIZADO"
                    })
                }

                if (showCustom) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                if (english) "Custom protections" else "Protecciones personalizadas",
                                style = MaterialTheme.typography.titleSmall
                            )
                            Text(
                                if (english)
                                    "Select the protections this app should use. Wi‑Fi and Mobile remain controlled above."
                                else
                                    "Seleccioná las protecciones que esta app debe usar. Wi‑Fi y Móvil siguen controlándose arriba.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.size(4.dp))
                            PromptCustomProtectionChecklist(
                                profile = customProfile,
                                english = english,
                                onProfileChange = { customProfile = it }
                            )
                            Spacer(Modifier.size(5.dp))
                            Button(
                                onClick = { onCustomDecision(wifi, mobile, customProfile) },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (english) "APPLY PERSONALIZED" else "APLICAR PERSONALIZADO")
                            }
                        }
                    }
                }

                Spacer(Modifier.size(8.dp))
                Text(
                    if (english) "Network access" else "Acceso de red",
                    style = MaterialTheme.typography.titleSmall
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    Text("Wi‑Fi")
                    Switch(checked = wifi, onCheckedChange = { wifi = it })
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    Text(if (english) "Mobile data" else "Datos móviles")
                    Switch(checked = mobile, onCheckedChange = { mobile = it })
                }
                Text(
                    if (english) "Wi‑Fi and Mobile apply to ALLOW and PERMISSIVE. BLOCK and NO FIREWALL ignore these switches."
                    else "Wi‑Fi y Datos móviles se aplican a PERMITIR y PERMISIVO. BLOQUEAR y SIN FIREWALL ignoran estos controles.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                val whyAttempt = groupedAttempts.firstOrNull()
                val whyReasons = remember(uid, packageName, whyAttempt?.destination, destination) {
                    ConnectionContext.explain(
                        context, uid, packageName.takeIf { it.isNotBlank() } ?: resolvedPackage,
                        whyAttempt?.destination ?: destination, whyAttempt?.protocolLabel ?: protocolLabel,
                        allowed = null, firstConnection = true
                    )
                }
                ConnectionWhyAlert(whyReasons, english)

                TextButton(
                    onClick = { showDetails = !showDetails },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (showDetails) "− ${if (english) "Details" else "Detalles"}" else "+ ${if (english) "Details" else "Detalles"}")
                }

                if (showDetails) {
                    Spacer(Modifier.size(8.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        ConnectionWhyBlock(whyReasons, english)
                        Text(if (english) "Connection" else "Conexión", style = MaterialTheme.typography.titleSmall)
                        Text("${if (english) "Network" else "Red"}: $triggeringNetwork", style = MaterialTheme.typography.bodySmall)
                        Text(
                            "${if (english) "Attempts" else "Intentos"}: ${if (groupedAttempts.isEmpty()) 1 else groupedAttempts.size}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        val shownAttempts = if (groupedAttempts.isEmpty()) {
                            listOf(DecisionRequestManager.Attempt(protocolLabel, destination))
                        } else groupedAttempts
                        shownAttempts.take(12).forEach { attempt ->
                            Text("• ${attempt.protocolLabel} · ${attempt.destination}", style = MaterialTheme.typography.bodySmall)
                        }

                        Text(if (english) "Identity" else "Identidad", style = MaterialTheme.typography.titleSmall)
                        Text("UID $uid", style = MaterialTheme.typography.bodySmall)
                        Text(packageName, style = MaterialTheme.typography.labelSmall, maxLines = 1)
                        if (uidPackages.size > 1) {
                            Text(if (english) "Shared UID packages" else "Paquetes con UID compartido", style = MaterialTheme.typography.labelMedium)
                            uidPackages.forEach { entry ->
                                Text("• ${entry.label} · ${entry.packageName}", style = MaterialTheme.typography.bodySmall, maxLines = 1)
                            }
                        }
                        Text(
                            if (runningProcesses.isEmpty()) {
                                "${if (english) "Process" else "Proceso"}: ${runCatching { context.packageManager.getApplicationInfo(packageName, 0).processName }.getOrNull() ?: packageName}"
                            } else {
                                "PID: ${runningProcesses.joinToString(", ") { it.pid.toString() }}"
                            },
                            style = MaterialTheme.typography.labelSmall
                        )

                        Text(if (english) "Android permissions" else "Permisos Android", style = MaterialTheme.typography.titleSmall)
                        if (permissionGroups.isEmpty() && uidPermissionPackages.none { it.groups.isNotEmpty() }) {
                            Text(
                                if (english) "No grouped permissions available." else "No hay permisos agrupados disponibles.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        } else {
                            uidPermissionPackages.filter { it.groups.isNotEmpty() }.forEach { pkg ->
                                if (uidPermissionPackages.size > 1) Text("${pkg.label} · ${pkg.packageName}", style = MaterialTheme.typography.labelMedium)
                                pkg.groups.forEach { group ->
                                    Text("${group.label} (${group.permissions.size})", style = MaterialTheme.typography.labelMedium)
                                    group.permissions.take(8).forEach { perm ->
                                        Text("• ${perm.substringAfterLast('.')}", style = MaterialTheme.typography.bodySmall)
                                    }
                                    if (group.permissions.size > 8) {
                                        Text(
                                            "… ${group.permissions.size - 8} ${if (english) "more" else "más"}",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }

                        Text(if (english) "NO FIREWALL" else "SIN FIREWALL", style = MaterialTheme.typography.titleSmall)
                        Text(
                            if (english) {
                                "For banking or special applications that do not allow use of a filtered network. The app uses Android's normal network and HYDRA does not inspect or block its traffic."
                            } else {
                                "Para aplicaciones bancarias o especiales que no permiten usar una red filtrada. La app usa la red normal de Android y HYDRA no inspecciona ni bloquea su tráfico."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PromptCustomProtectionChecklist(
    profile: CustomProtectionProfileStore.Profile,
    english: Boolean,
    onProfileChange: (CustomProtectionProfileStore.Profile) -> Unit
) {
    @Composable
    fun row(title: String, subtitle: String, checked: Boolean, set: (Boolean) -> CustomProtectionProfileStore.Profile) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 6.dp)) {
                Text(title, style = MaterialTheme.typography.bodyMedium)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = { onProfileChange(set(it)) })
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
        if (english) "TLS fingerprint protection" else "Protección por huella TLS",
        if (english) "Enforce the optional JA3/JA3N known-bad list." else "Aplica la lista opcional de huellas JA3/JA3N conocidas.",
        profile.tlsFingerprint
    ) { profile.copy(tlsFingerprint = it) }
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

@Composable
private fun PromptAction(
    buttonText: String,
    description: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Button(
            onClick = onClick,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(buttonText, maxLines = 2, softWrap = true, style = MaterialTheme.typography.labelLarge)
        }
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 3.dp),
            maxLines = 3,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
        )
    }
}

private fun settingsTheme(context: android.content.Context): ThemeMode {
    return runCatching {
        context.getSharedPreferences("firewall_settings", android.content.Context.MODE_PRIVATE)
            .getString("theme_mode", ThemeMode.SYSTEM.name)
            ?.let(ThemeMode::valueOf)
    }.getOrNull() ?: ThemeMode.SYSTEM
}

private fun formatEndpoint(addr: java.net.InetAddress, port: Int): String {
    val host = addr.hostAddress ?: "?"
    return if (host.contains(':')) "[$host]:$port" else "$host:$port"
}
