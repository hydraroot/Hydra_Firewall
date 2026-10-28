package com.hydra.firewall

import android.Manifest
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

class MainActivity : AppCompatActivity() {
    private var appLocked by mutableStateOf(false)
    private var lastBackgroundMs = 0L
    private val lockStore by lazy { LockStore(this) }
    private var pendingCsv: String? = null
    private var pendingKillSwitchSettings = false

    private val csvCreateLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        uri ?: return@registerForActivityResult
        val csv = pendingCsv ?: return@registerForActivityResult
        runCatching {
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(byteOrderMark.toByteArray(Charsets.UTF_8))
                out.write(csv.toByteArray(Charsets.UTF_8))
            }
        }
        pendingCsv = null
    }

    private val vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startFirewallService()
            if (pendingKillSwitchSettings) {
                pendingKillSwitchSettings = false
                window.decorView.postDelayed({ openVpnSettings() }, 250)
            }
        } else {
            pendingKillSwitchSettings = false
        }
    }
    private val notificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ConnectionHistory.init(this)
        TrafficAnalyzerStore.init(this)
        TlsFingerprintStore.init(this)
        AppNetworkProfileStore.init(this)
        ServiceTamperMonitor.init(this)
        appLocked = lockStore.enabled && lockStore.configured
        setContent {
            if (appLocked) {
                LockScreen(lockStore) { appLocked = false }
            } else {
                FirewallScreen(onToggle = ::handleToggle, onRequestNotifications = ::requestNotifications, onExportHistory = ::exportHistoryCsv, onKillSwitch = ::configureKillSwitch)
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (lockStore.enabled && lockStore.configured && !isChangingConfigurations) {
            lastBackgroundMs = System.currentTimeMillis()
        }
    }

    override fun onStart() {
        super.onStart()
        if (lastBackgroundMs > 0L && lockStore.enabled && lockStore.configured &&
            System.currentTimeMillis() - lastBackgroundMs >= 30_000L) {
            appLocked = true
        }
    }

    private fun handleToggle(turnOn: Boolean) { if (turnOn) requestVpnPermissionAndStart() else stopFirewallService() }
    private fun configureKillSwitch() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingKillSwitchSettings = true
            vpnPermissionLauncher.launch(intent)
        } else {
            startFirewallService()
            window.decorView.postDelayed({ openVpnSettings() }, 250)
        }
    }
    private fun openVpnSettings() {
        startActivitySafe(this, Settings.ACTION_VPN_SETTINGS)
    }
    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    private fun requestVpnPermissionAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else startFirewallService()
    }
    private fun startFirewallService() {
        val intent = Intent(this, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_START }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
    }

    private fun exportHistoryCsv() {
        pendingCsv = buildHistoryCsv(ConnectionHistory.snapshot())
        csvCreateLauncher.launch("firewall-historial-${System.currentTimeMillis()}.csv")
    }

    private fun stopFirewallService() {
        val intent = Intent(this, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_STOP }
        startService(intent)
    }
}

data class AppEntry(val label: String, val packageName: String, val uid: Int, val isSystem: Boolean, val processName: String)

enum class ThemeMode { SYSTEM, LIGHT, DARK }
enum class RuleFilter { ALL, BLOCKED }

enum class MainTab { PROTECTION, RULES, IP_PORTS, CONNECTIONS, ANALYZER, STATS, PROFILES, SECURITY, SELFTEST, SETTINGS, HELP, ABOUT }
enum class AppListFilter { ALL, USER, SYSTEM, FAVORITES, HIGH_ACTIVITY }
enum class AppSort { NAME, TRAFFIC, CONNECTIONS }

sealed class BlockAdsCheckState {
    object Idle : BlockAdsCheckState()
    object Checking : BlockAdsCheckState()
    object UpToDate : BlockAdsCheckState()
    data class CheckFailed(val error: String?) : BlockAdsCheckState()
    data class NewAvailable(val remoteDate: String) : BlockAdsCheckState()
    object Updating : BlockAdsCheckState()
    data class UpdateSuccess(val domainCount: Int) : BlockAdsCheckState()
    data class UpdateSkipped(val remoteDate: String, val domainCount: Int) : BlockAdsCheckState()
    data class UpdateFailed(val error: String?) : BlockAdsCheckState()
}

@Composable
private fun hydraDialogColors(): Triple<Color, Color, Color> {
    val dark = MaterialTheme.colorScheme.background.luminance() < 0.5f
    return if (dark) {
        Triple(Color(0xFF1C1B1F), Color(0xFFE6E1E5), Color(0xFFE6E1E5))
    } else {
        Triple(Color(0xFFFFFBFE), Color(0xFF1C1B1F), Color(0xFF1C1B1F))
    }
}


private fun Modifier.hydraNeon(active: Boolean, color: Color = Color(0xFF00C9B7)): Modifier =
    if (active) this.shadow(
        elevation = 2.dp,
        shape = RoundedCornerShape(12.dp),
        clip = false
    ) else this

enum class RuleSubTab { APPS, IPS, PORTS }

enum class GlobalMode { BLACKLIST, WHITELIST }

@Composable
fun FirewallScreen(
    onToggle: (Boolean) -> Unit,
    onRequestNotifications: () -> Unit,
    onExportHistory: () -> Unit,
    onKillSwitch: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val ruleStore = remember { RuleStore(context.applicationContext) }
    val settingsStore = remember { AppSettings(context.applicationContext) }
    val ipBlockStore = remember { IpBlockStore(context.applicationContext) }
    val advancedRuleStore = remember { AdvancedRuleStore(context.applicationContext) }
    val customProtectionStore = remember { CustomProtectionProfileStore(context.applicationContext) }
    val profilesStore = remember { ProfilesStore(context.applicationContext) }
    val favoritesStore = remember { AppFavoritesStore(context.applicationContext) }
    val essentialAppsStore = remember { EssentialAppsStore(context.applicationContext) }
    val appSettings = remember { AppSettings(context.applicationContext) }
    remember { AppCompatibilityPolicyStore.init(context.applicationContext); true }
    remember { DomainBlockStore.init(context.applicationContext); true }

    var isOn by remember { mutableStateOf(FirewallVpnService.isRunning) }
    var showAlwaysOnPrompt by remember { mutableStateOf(false) }
    LaunchedEffect(isOn) {
        if (isOn && !appSettings.alwaysOnPromptShown) {
            // Esperamos a que FirewallVpnService.startVpn() termine de correr (establish()
            // + el resto de la configuración) antes de decidir si vale la pena mostrar el
            // aviso; no es crítico acertar el timing exacto porque igual lo mostramos una
            // sola vez en la vida de la instalación.
            delay(600)
            if (isOn) {
                showAlwaysOnPrompt = true
                appSettings.alwaysOnPromptShown = true
            }
        }
    }
    var network by remember { mutableStateOf(FirewallVpnService.currentNetworkKind) }
    var roaming by remember { mutableStateOf(FirewallVpnService.currentRoaming) }
    var apps by remember { mutableStateOf(emptyList<AppEntry>()) }
    var appsLoading by remember { mutableStateOf(true) }
    var selectedTab by remember { mutableStateOf(MainTab.PROTECTION) }
    var advancedMode by remember { mutableStateOf(settingsStore.advancedMode) }
    val advancedOnlyTabs = setOf(MainTab.IP_PORTS, MainTab.ANALYZER, MainTab.PROFILES, MainTab.SELFTEST)
    val visibleTabs = MainTab.values().filter { advancedMode || it !in advancedOnlyTabs }
    if (selectedTab !in visibleTabs) selectedTab = MainTab.PROTECTION
    var search by remember { mutableStateOf("") }
    var showSystemApps by remember { mutableStateOf(settingsStore.showSystemApps) }
    var trustedAppsEnabled by remember { mutableStateOf(settingsStore.trustedAppsEnabled) }
    var systemAppsWarning by remember { mutableStateOf(false) }
    var themeMode by remember { mutableStateOf(settingsStore.themeMode) }
    var filter by remember { mutableStateOf(RuleFilter.ALL) }
    var appListFilter by remember { mutableStateOf(AppListFilter.USER) }
    var appSort by remember { mutableStateOf(AppSort.NAME) }
    var ruleSubTab by remember { mutableStateOf(RuleSubTab.APPS) }
    var selectedApp by remember { mutableStateOf<AppEntry?>(null) }
    var selectedCustomApp by remember { mutableStateOf<AppEntry?>(null) }
    var selectedScheduleApp by remember { mutableStateOf<AppEntry?>(null) }
    var ruleVersion by remember { mutableStateOf(0) }
    var refreshTrigger by remember { mutableStateOf(0) }
    var ipVersion by remember { mutableStateOf(0) }
    var blockedIpInput by remember { mutableStateOf("") }
    var networkRuleSubTab by remember { mutableStateOf(0) }
    var rulesSubTab by remember { mutableStateOf(0) }
    var history by remember { mutableStateOf(ConnectionHistory.snapshot()) }
    var stats by remember { mutableStateOf(TrafficStatsStore.snapshotAll()) }
    var trafficTotals by remember { mutableStateOf(TrafficStatsStore.totals()) }
    var trafficHistory by remember { mutableStateOf(listOf(0f to 0f)) }
    var showGlobalBlockDialog by remember { mutableStateOf(false) }
    var historySort by remember { mutableStateOf(HistorySort.TIME) }
    var historySortMenu by remember { mutableStateOf(false) }
    var groupedHistory by remember { mutableStateOf(true) }
    var profileName by remember { mutableStateOf("") }
    var profileVersion by remember { mutableStateOf(0) }
    var advancedVersion by remember { mutableStateOf(0) }
    var retentionHours by remember { mutableStateOf(ConnectionHistory.retentionHours(context)) }
    var showResetDialog by remember { mutableStateOf(false) }
    var globalMode by remember { mutableStateOf(runCatching { GlobalMode.valueOf(ruleStore.policyMode) }.getOrDefault(GlobalMode.BLACKLIST)) }
    var defaultWifi by remember { mutableStateOf(ruleStore.defaultWifiAllowed) }
    var defaultMobile by remember { mutableStateOf(ruleStore.defaultMobileAllowed) }
    var askFirst by remember { mutableStateOf(ruleStore.askOnFirstConnection) }
    var learningMode by remember { mutableStateOf(ruleStore.learningMode) }
    var lowPowerMode by remember { mutableStateOf(appSettings.lowPowerMode) }
    var pauseUiScreenOff by remember { mutableStateOf(appSettings.pauseUiWhenScreenOff) }
    var uiRefreshSeconds by remember { mutableStateOf(appSettings.uiRefreshSeconds) }
    var historyMaxRecords by remember { mutableStateOf(appSettings.historyMaxRecords) }
    var showEssentialDialog by remember { mutableStateOf(false) }
    var invalidAllowed by remember { mutableStateOf(ruleStore.invalidUidAllowed) }
    var allowLocal by remember { mutableStateOf(ruleStore.allowLocalNetwork) }
    var blockIpv6 by remember { mutableStateOf(ruleStore.blockIpv6) }
    var blockRoaming by remember { mutableStateOf(ruleStore.blockWhenRoaming) }
    var blockScreenOff by remember { mutableStateOf(ruleStore.blockWhenScreenOff) }
    var secureDns by remember { mutableStateOf(ruleStore.secureDnsEnabled) }
    var dnsProvider by remember { mutableStateOf(ruleStore.dnsProvider) }
    var dnsTransport by remember { mutableStateOf(ruleStore.dnsTransport) }
    var customDnsIpv4 by remember { mutableStateOf(ruleStore.customDnsIpv4) }
    var customDnsIpv6 by remember { mutableStateOf(ruleStore.customDnsIpv6) }
    var customDnsHostname by remember { mutableStateOf(ruleStore.customDnsHostname) }
    var customDnsDohUrl by remember { mutableStateOf(ruleStore.customDnsDohUrl) }
    var blockAdsEnabled by remember { mutableStateOf(DomainBlockStore.enabled) }
    var threatProtectionEnabled by remember { mutableStateOf(ruleStore.threatProtectionEnabled || DomainBlockStore.enabled) }
    var blockAdsListInfo by remember { mutableStateOf(DomainBlockStore.activeListInfo()) }
    var blocklistProtectionRevision by remember { mutableIntStateOf(0) }
    var blockAdsBlockedToday by remember { mutableStateOf(DomainBlockStore.blockedToday()) }
    var blockAdsCheckState by remember { mutableStateOf<BlockAdsCheckState>(BlockAdsCheckState.Idle) }
    var globalBlockAll by remember { mutableStateOf(ruleStore.globalBlockAll) }
    var language by remember { mutableStateOf(settingsStore.language) }

    LaunchedEffect(refreshTrigger) {
        appsLoading = true
        try {
            apps = withContext(Dispatchers.IO) { loadNetworkApps(context) }
        } finally {
            appsLoading = false
        }
    }
    LaunchedEffect(uiRefreshSeconds, lowPowerMode, pauseUiScreenOff) {
        var lastAllowed = TrafficStatsStore.totals().allowedBytes
        var lastBlocked = TrafficStatsStore.totals().blockedBytes
        while (true) {
            val interactive = runCatching {
                val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
                if (Build.VERSION.SDK_INT >= 20) pm.isInteractive else true
            }.getOrDefault(true)
            isOn = FirewallVpnService.isRunning
            network = FirewallVpnService.currentNetworkKind
            roaming = FirewallVpnService.currentRoaming
            if (!(pauseUiScreenOff && !interactive)) {
                history = ConnectionHistory.snapshot()
                stats = TrafficStatsStore.snapshotAll()
                val totals = TrafficStatsStore.totals()
                trafficTotals = totals
                blockAdsBlockedToday = DomainBlockStore.blockedToday()
                val allowedDeltaMb = (totals.allowedBytes - lastAllowed).coerceAtLeast(0L) / (1024f * 1024f)
                val blockedDeltaMb = (totals.blockedBytes - lastBlocked).coerceAtLeast(0L) / (1024f * 1024f)
                lastAllowed = totals.allowedBytes
                lastBlocked = totals.blockedBytes
                trafficHistory = (trafficHistory + (allowedDeltaMb to blockedDeltaMb)).takeLast(60)
            }
            delay((if (lowPowerMode) maxOf(4, uiRefreshSeconds + 2) else uiRefreshSeconds).toLong() * 1000L)
        }
    }

    val distinctHistoryHosts = remember(history) {
        history.map { extractHost(it.destination) }.filter { it.isNotBlank() }.distinct()
    }
    LaunchedEffect(distinctHistoryHosts) {
        withContext(Dispatchers.IO) {
            distinctHistoryHosts.forEach { host -> DomainResolver.resolve(host) }
        }
    }

    val darkTheme = when (themeMode) { ThemeMode.DARK -> true; ThemeMode.LIGHT -> false; ThemeMode.SYSTEM -> isSystemInDarkTheme() }
    val protection = remember(isOn, secureDns, threatProtectionEnabled, blockAdsEnabled, blockAdsListInfo, blocklistProtectionRevision) {
        ProtectionStatus.read(context)
    }

    FirewallLocalTheme(darkTheme = darkTheme) {
        Scaffold { padding ->
            Column(modifier = modifier.fillMaxSize().padding(padding)) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Image(
                                painter = androidx.compose.ui.res.painterResource(com.hydra.firewall.R.drawable.ic_header_logo),
                                contentDescription = "Hydra Firewall",
                                modifier = Modifier.size(30.dp).clip(CircleShape)
                            )
                            Spacer(Modifier.width(8.dp))
                            val headerProtection = ProtectionStatus.read(context)
                            Column {
                                Text("Hydra Firewall", style = MaterialTheme.typography.titleSmall)
                                Text(
                                    when (headerProtection.level) {
                                        ProtectionStatus.Level.ACTIVE -> if (language == AppLanguage.EN) "PROTECTION ON" else "PROTECCIÓN ACTIVADA"
                                        ProtectionStatus.Level.PARTIAL -> if (language == AppLanguage.EN) "PROTECTION PARTIAL" else "PROTECCIÓN PARCIAL"
                                        ProtectionStatus.Level.OFF -> if (language == AppLanguage.EN) "PROTECTION OFF" else "PROTECCIÓN DESACTIVADA"
                                    },
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = when (headerProtection.level) {
                                        ProtectionStatus.Level.ACTIVE -> Color(0xFF2E8B57)
                                        ProtectionStatus.Level.PARTIAL -> Color(0xFFD98E1F)
                                        ProtectionStatus.Level.OFF -> MaterialTheme.colorScheme.error
                                    }
                                )
                            }
                        }
                    }
                    // Botón claro/oscuro: icono mitad negro / mitad blanco, a la derecha, sin ocupar alto extra.
                    val toggleBorder = MaterialTheme.colorScheme.onSurface
                    Canvas(
                        Modifier
                            .size(30.dp)
                            .clip(CircleShape)
                            .clickable {
                                val next = if (darkTheme) ThemeMode.LIGHT else ThemeMode.DARK
                                themeMode = next
                                settingsStore.themeMode = next
                            }
                    ) {
                        val r = size.minDimension / 2f
                        drawCircle(Color.White, radius = r)
                        drawArc(
                            color = Color.Black, startAngle = 90f, sweepAngle = 180f, useCenter = true
                        )
                        drawCircle(toggleBorder, radius = r - 1f, style = Stroke(width = 2f))
                    }
                }
                ScrollableTabRow(selectedTabIndex = visibleTabs.indexOf(selectedTab).coerceAtLeast(0), edgePadding = 4.dp) {
                    visibleTabs.forEachIndexed { index, tab ->
                        Tab(
                            index == visibleTabs.indexOf(selectedTab),
                            { selectedTab = tab },
                            text = {
                                Text(
                                    when (tab) {
                                        MainTab.PROTECTION -> if (language == AppLanguage.EN) "PROTECTION" else "PROTECCIÓN"
                                        MainTab.RULES -> tr(context,"rules")
                                        MainTab.IP_PORTS -> tr(context,"ip_ports")
                                        MainTab.CONNECTIONS -> tr(context,"connections")
                                        MainTab.ANALYZER -> if (language == AppLanguage.EN) "ANALYZER" else "ANALIZADOR"
                                        MainTab.STATS -> tr(context,"stats")
                                        MainTab.PROFILES -> tr(context,"profiles")
                                        MainTab.SECURITY -> if (language == AppLanguage.EN) "SECURITY" else "SEGURIDAD"
                                        MainTab.SELFTEST -> if (language == AppLanguage.EN) "TEST" else "PRUEBA"
                                        MainTab.SETTINGS -> tr(context,"settings")
                                        MainTab.HELP -> tr(context,"help")
                                        MainTab.ABOUT -> tr(context,"about")
                                    }.uppercase(),
                                    style = MaterialTheme.typography.labelMedium,
                                    maxLines = 1
                                )
                            }
                        )
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth().height(18.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        if (AppSettings(context).language == AppLanguage.EN) "← more tabs →" else "← más pestañas →",
                        fontSize = 9.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                when (selectedTab) {
                    MainTab.PROTECTION -> {
                        ProtectionTabContent(
                            advancedMode = advancedMode,
                            onAdvancedModeChange = { advancedMode = it; settingsStore.advancedMode = it },
                            context = context,
                            language = language,
                            protection = protection,
                            isOn = isOn,
                            network = network,
                            roaming = roaming,
                            globalBlockAll = globalBlockAll,
                            threatProtectionEnabled = threatProtectionEnabled,
                            blockAdsListInfo = blockAdsListInfo,
                            blockAdsBlockedToday = blockAdsBlockedToday,
                            blockAdsCheckState = blockAdsCheckState,
                            onToggleVpn = onToggle,
                            onGlobalBlockAllChange = { enabled ->
                                globalBlockAll = enabled
                                ruleStore.globalBlockAll = enabled
                                notifyRulesChanged(context)
                            },
                            onThreatProtectionChange = { enabled ->
                                threatProtectionEnabled = enabled
                                ruleStore.threatProtectionEnabled = enabled
                                blockAdsEnabled = enabled
                                DomainBlockStore.enabled = enabled
                                if (enabled) {
                                    secureDns = true
                                    ruleStore.secureDnsEnabled = true
                                }
                                blocklistProtectionRevision++
                                notifyRulesChanged(context)
                            },
                            onCheckBlocklist = {
                                blockAdsCheckState = BlockAdsCheckState.Checking
                                BlocklistUpdater.checkForUpdate(context) { result ->
                                    (context as? android.app.Activity)?.runOnUiThread {
                                        blockAdsCheckState = when {
                                            result.remoteDate != null && result.newAvailable ->
                                                BlockAdsCheckState.NewAvailable(result.remoteDate)
                                            result.remoteDate != null -> BlockAdsCheckState.UpToDate
                                            else -> BlockAdsCheckState.CheckFailed(result.error)
                                        }
                                    }
                                }
                            },
                            onUpdateBlocklist = {
                                blockAdsCheckState = BlockAdsCheckState.Updating
                                BlocklistUpdater.downloadAndApply(context) { result ->
                                    (context as? android.app.Activity)?.runOnUiThread {
                                        blockAdsListInfo = DomainBlockStore.activeListInfo()
                                        blockAdsBlockedToday = DomainBlockStore.blockedToday()
                                        blocklistProtectionRevision++
                                        blockAdsCheckState = if (result.success) {
                                            if (result.skipped) {
                                                BlockAdsCheckState.UpdateSkipped(result.remoteDate ?: blockAdsListInfo.date, result.domainCount)
                                            } else {
                                                BlockAdsCheckState.UpdateSuccess(result.domainCount)
                                            }
                                        } else {
                                            BlockAdsCheckState.UpdateFailed(result.error)
                                        }
                                    }
                                }
                            },
                            onKillSwitch = onKillSwitch
                        )
                    }
                    MainTab.RULES -> {
                        Column(Modifier.fillMaxSize().padding(horizontal = 10.dp)) {
                            HydraHorizontalRow(Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 2.dp)) {
                                HydraChoiceButton(
                                    rulesSubTab == 0,
                                    if (language == AppLanguage.EN) "APPS" else "APLICACIONES",
                                    Color(0xFFE3D0FF), Color(0xFF241A34),
                                    onClick = { rulesSubTab = 0 }, modifier = Modifier.height(26.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                                HydraChoiceButton(
                                    rulesSubTab == 1,
                                    if (language == AppLanguage.EN) "DOMAINS" else "DOMINIOS",
                                    Color(0xFFE3D0FF), Color(0xFF241A34),
                                    onClick = { rulesSubTab = 1 }, modifier = Modifier.height(26.dp)
                                )
                            }
                            if (rulesSubTab == 0) {
                            // Buscador compacto (36 dp): el OutlinedTextField mide como mínimo 56 dp y, forzado a menos,
                            // su etiqueta se montaba sobre la fila de botones de abajo.
                            androidx.compose.foundation.text.BasicTextField(
                                value = search,
                                onValueChange = { search = it },
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface,
                                    fontSize = 14.sp
                                ),
                                cursorBrush = androidx.compose.ui.graphics.SolidColor(MaterialTheme.colorScheme.primary),
                                modifier = Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 4.dp).height(36.dp),
                                decorationBox = { inner ->
                                    Row(
                                        Modifier
                                            .fillMaxSize()
                                            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(10.dp))
                                            .padding(horizontal = 10.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                                            if (search.isEmpty()) {
                                                Text(
                                                    tr(context, "search_app"),
                                                    fontSize = 13.sp,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    maxLines = 1
                                                )
                                            }
                                            inner()
                                        }
                                        if (search.isNotEmpty()) {
                                            Text(
                                                "✕",
                                                fontSize = 14.sp,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.clickable { search = "" }.padding(start = 8.dp)
                                            )
                                        }
                                    }
                                }
                            )
                            Spacer(Modifier.height(2.dp))
                            if (advancedMode) Text(
                                if (language == AppLanguage.EN)
                                    "Apps de confianza: when enabled, apps installed from Google Play or platform-signed system apps can be auto-allowed. New ordinary apps still prompt when this is off."
                                else
                                    "Apps de confianza: activado permite autorizar automáticamente apps instaladas desde Google Play o apps de sistema firmadas por la plataforma. Con el interruptor apagado, las apps nuevas preguntan."
                                ,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                            )
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(30.dp).padding(vertical = 2.dp)) {
                                HydraChoiceButton(
                                    selected = appListFilter == AppListFilter.USER,
                                    label = if(language==AppLanguage.EN) "User" else "Usuario",
                                    selectedColor = Color(0xFF2D79B7),
                                    selectedLabelColor = Color.White,
                                    onClick = { appListFilter = if (appListFilter == AppListFilter.USER) AppListFilter.ALL else AppListFilter.USER },
                                    modifier = Modifier.widthIn(min = 94.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = filter == RuleFilter.ALL && appListFilter == AppListFilter.ALL,
                                    label = tr(context,"all"),
                                    selectedColor = Color(0xFFE3D0FF),
                                    selectedLabelColor = Color(0xFF241A34),
                                    onClick = { filter = RuleFilter.ALL; appListFilter = AppListFilter.ALL; systemAppsWarning = true },
                                    modifier = Modifier.widthIn(min = 82.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = filter == RuleFilter.BLOCKED,
                                    label = tr(context,"blocked"),
                                    selectedColor = Color(0xFFB83A46),
                                    selectedLabelColor = Color.White,
                                    unselectedLabelColor = Color(0xFF8F2F39),
                                    onClick = { filter = if (filter == RuleFilter.BLOCKED) RuleFilter.ALL else RuleFilter.BLOCKED },
                                    modifier = Modifier.widthIn(min = 112.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = appListFilter == AppListFilter.SYSTEM,
                                    label = if(language==AppLanguage.EN) "System" else "Sistema",
                                    selectedColor = Color(0xFF8B6B00),
                                    selectedLabelColor = Color(0xFFFFF4B0),
                                    unselectedLabelColor = Color(0xFF856600),
                                    onClick = { if (appListFilter == AppListFilter.SYSTEM) appListFilter = AppListFilter.ALL else { systemAppsWarning = true; appListFilter = AppListFilter.SYSTEM } },
                                    modifier = Modifier.widthIn(min = 94.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = appListFilter == AppListFilter.FAVORITES,
                                    label = "★",
                                    selectedColor = Color(0xFF8A44B8),
                                    selectedLabelColor = Color.White,
                                    unselectedLabelColor = Color(0xFF7B3FA0),
                                    onClick = { appListFilter = if (appListFilter == AppListFilter.FAVORITES) AppListFilter.ALL else AppListFilter.FAVORITES },
                                    modifier = Modifier.width(54.dp),
                                    fontSize = 14.sp
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = appListFilter == AppListFilter.HIGH_ACTIVITY,
                                    label = if (language == AppLanguage.EN) "Active" else "Activas",
                                    selectedColor = Color(0xFF1E659B),
                                    selectedLabelColor = Color(0xFFD6F1FF),
                                    unselectedLabelColor = Color(0xFF1E659B),
                                    onClick = { appListFilter = if (appListFilter == AppListFilter.HIGH_ACTIVITY) AppListFilter.ALL else AppListFilter.HIGH_ACTIVITY },
                                    modifier = Modifier.widthIn(min = 86.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = trustedAppsEnabled,
                                    label = if (language == AppLanguage.EN) "Trusted ✓" else "Confianza ✓",
                                    selectedColor = Color(0xFF2E8B57),
                                    selectedLabelColor = Color.White,
                                    unselectedLabelColor = Color(0xFF2E8B57),
                                    onClick = {
                                        trustedAppsEnabled = !trustedAppsEnabled
                                        settingsStore.trustedAppsEnabled = trustedAppsEnabled
                                        ruleVersion++
                                        notifyRulesChanged(context)
                                    },
                                    modifier = Modifier.widthIn(min = 98.dp)
                                )
                                Spacer(Modifier.width(5.dp))
                                HydraChoiceButton(
                                    selected = false,
                                    label = "↻",
                                    selectedColor = Color(0xFFE3D0FF),
                                    onClick = { refreshTrigger++; ruleVersion++ },
                                    modifier = Modifier.width(44.dp),
                                    fontSize = 14.sp
                                )
                            }
                            val query = search.trim().lowercase()
                            val baseApps = apps.filter { app ->
                                true &&
                                    (query.isEmpty() || app.label.lowercase().contains(query) || app.packageName.lowercase().contains(query) || app.uid.toString().contains(query) || app.processName.lowercase().contains(query))
                            }.filter { app ->
                                val rule = ruleStore.getRule(app.uid)
                                val explicit = ruleStore.hasExplicitRule(app.uid)
                                val autoEssential = essentialAppsStore.isAutoEssential(app.uid)
                                val userEssential = essentialAppsStore.isUserEssential(app.uid)
                                val trustedAuto = trustedAppsEnabled && TrustedAppsDetector.isTrusted(context, app.uid)
                                val effectiveWifi = if (!explicit && (autoEssential || trustedAuto)) true else rule.wifiAllowed
                                val effectiveMobile = if (!explicit && (autoEssential || trustedAuto)) true else rule.mobileAllowed
                                filter == RuleFilter.ALL || !effectiveWifi || !effectiveMobile
                            }.filter { app ->
                                when (appListFilter) {
                                    AppListFilter.ALL -> true
                                    AppListFilter.USER -> !app.isSystem
                                    AppListFilter.SYSTEM -> app.isSystem
                                    AppListFilter.FAVORITES -> favoritesStore.isFavorite(app.uid)
                                    AppListFilter.HIGH_ACTIVITY -> TrafficStatsStore.snapshot(app.uid).connections >= 50L
                                }
                            }
                            val visibleApps = when (appSort) {
                                AppSort.NAME -> baseApps.sortedBy { it.label.lowercase() }
                                AppSort.TRAFFIC -> baseApps.sortedByDescending { val x=TrafficStatsStore.snapshot(it.uid); x.txBytes + x.rxBytes }
                                AppSort.CONNECTIONS -> baseApps.sortedByDescending { TrafficStatsStore.snapshot(it.uid).connections }
                            }
                            val rulesListState = androidx.compose.foundation.lazy.rememberLazyListState()
                            Box(Modifier.weight(1f)) {
                            if (appsLoading && apps.isEmpty()) {
                                Column(
                                    Modifier.fillMaxSize(),
                                    horizontalAlignment = Alignment.CenterHorizontally,
                                    verticalArrangement = Arrangement.Center
                                ) {
                                    CircularProgressIndicator(modifier = Modifier.size(28.dp), strokeWidth = 3.dp)
                                    Spacer(Modifier.height(10.dp))
                                    Text(
                                        if (language == AppLanguage.EN) "Loading applications…" else "Cargando aplicaciones…",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                }
                            }
                            LazyColumn(Modifier.fillMaxSize(), state = rulesListState) {
                                items(visibleApps, key = { "${it.packageName}:${it.uid}" }) { app ->
                                    val rule = remember(ruleVersion) { ruleStore.getRule(app.uid) }
                                    val explicitRule = ruleStore.hasExplicitRule(app.uid)
                                    val autoEssential = essentialAppsStore.isAutoEssential(app.uid)
                                    val userEssential = essentialAppsStore.isUserEssential(app.uid)
                                    val compatibilityMode = AppCompatibilityPolicyStore.getMode(app.packageName)
                                    val customized = compatibilityMode == AppCompatibilityMode.CUSTOM
                                    val compatibilityExcluded = compatibilityMode == AppCompatibilityMode.EXCLUDED
                                    val trustedAutoAllowed = trustedAppsEnabled && TrustedAppsDetector.isTrusted(context, app.uid)
                                    val effectiveWifi = if (!explicitRule && (autoEssential || trustedAutoAllowed)) true else rule.wifiAllowed
                                    val effectiveMobile = if (!explicitRule && (autoEssential || trustedAutoAllowed)) true else rule.mobileAllowed
                                    AppRuleRow(app, effectiveWifi, effectiveMobile, explicitRule, autoEssential, userEssential, customized, trustedAutoAllowed, compatibilityExcluded, ruleStore.getSchedule(app.uid).enabled, favoritesStore.isFavorite(app.uid),
                                        { checked ->
                                            // App sin regla propia: al permitirla se activan Wi‑Fi y móvil juntos; al bloquear una red
                                            // se conserva lo que se veía en pantalla para la otra (no se pierde por el valor por defecto).
                                            val mobileAfter = if (!explicitRule) (checked || effectiveMobile) else effectiveMobile
                                            if (!explicitRule) ruleStore.setMobileAllowed(app.uid, mobileAfter)
                                            ruleStore.setWifiAllowed(app.uid, checked); ruleVersion++; notifyRulesChanged(context)
                                            android.widget.Toast.makeText(context, describeAppPolicy(AppCompatibilityPolicyStore.getMode(app.packageName), checked, mobileAfter, true, trustedAutoAllowed, settingsStore.language == AppLanguage.EN), android.widget.Toast.LENGTH_SHORT).show()
                                        },
                                        { checked ->
                                            val wifiAfter = if (!explicitRule) (checked || effectiveWifi) else effectiveWifi
                                            if (!explicitRule) ruleStore.setWifiAllowed(app.uid, wifiAfter)
                                            ruleStore.setMobileAllowed(app.uid, checked); ruleVersion++; notifyRulesChanged(context)
                                            android.widget.Toast.makeText(context, describeAppPolicy(AppCompatibilityPolicyStore.getMode(app.packageName), wifiAfter, checked, true, trustedAutoAllowed, settingsStore.language == AppLanguage.EN), android.widget.Toast.LENGTH_SHORT).show()
                                        },
                                        {
                                            AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.NORMAL)
                                            ruleVersion++
                                            notifyRulesChanged(context)
                                            android.widget.Toast.makeText(context, describeAppPolicy(AppCompatibilityMode.NORMAL, effectiveWifi, effectiveMobile, explicitRule, trustedAutoAllowed, settingsStore.language == AppLanguage.EN), android.widget.Toast.LENGTH_SHORT).show()
                                        },
                                        {
                                            // Selecting ESENCIAL here is an explicit user grant.
                                            // For a never-configured app, the stored default is
                                            // BLOCK/BLOCK; preserving those defaults would make
                                            // "Hacer esencial" appear to work while leaving the
                                            // app offline. Grant both networks only when there is
                                            // no explicit rule. Existing explicit restrictions are
                                            // preserved and remain user-authoritative.
                                            val targetWifi = if (!explicitRule) true else effectiveWifi
                                            val targetMobile = if (!explicitRule) true else effectiveMobile
                                            ruleStore.setWifiAllowed(app.uid, targetWifi)
                                            ruleStore.setMobileAllowed(app.uid, targetMobile)
                                            AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.ESSENTIAL)
                                            ruleVersion++
                                            notifyRulesChanged(context)
                                            android.widget.Toast.makeText(context, describeAppPolicy(AppCompatibilityMode.ESSENTIAL, targetWifi, targetMobile, true, false, settingsStore.language == AppLanguage.EN), android.widget.Toast.LENGTH_SHORT).show()
                                        },
                                        { favoritesStore.toggle(app.uid); ruleVersion++ },
                                        { selectedCustomApp = app },
                                        { selectedApp = app },
                                        { selectedScheduleApp = app },
                                        {
                                            val current = AppCompatibilityPolicyStore.getMode(app.packageName)
                                            val target = if (current == AppCompatibilityMode.EXCLUDED) AppCompatibilityMode.NORMAL else AppCompatibilityMode.EXCLUDED
                                            AppCompatibilityController.setModeAndRestart(context, app.packageName, target)
                                            ruleVersion++
                                            notifyRulesChanged(context)
                                            val targetWifi = if (target == AppCompatibilityMode.NORMAL) rule.wifiAllowed else false
                                            val targetMobile = if (target == AppCompatibilityMode.NORMAL) rule.mobileAllowed else false
                                            val targetExplicit = if (target == AppCompatibilityMode.NORMAL) explicitRule else false
                                            val targetSummary = describeAppPolicy(target, targetWifi, targetMobile, targetExplicit, false, settingsStore.language == AppLanguage.EN)
                                            android.widget.Toast.makeText(context, targetSummary, android.widget.Toast.LENGTH_SHORT).show()
                                        })
                                    HorizontalDivider()
                                }
                            }
                                if (rulesListState.canScrollForward) {
                                    Text(
                                        if (language == AppLanguage.EN) "▼ more below" else "▼ hay más abajo",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 4.dp)
                                            .clip(RoundedCornerShape(10.dp))
                                            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.85f))
                                            .padding(horizontal = 10.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }
                            else {
                                DomainRulesPanel(
                                    context = context,
                                    english = language == AppLanguage.EN,
                                    version = refreshTrigger + rulesSubTab,
                                    onChanged = {
                                        ruleVersion++
                                        notifyRulesChanged(context)
                                    }
                                )
                            }
                        }
                    }
                    MainTab.IP_PORTS -> {
                        Column(Modifier.fillMaxSize().padding(horizontal = 10.dp)) {
                            HydraHorizontalRow(Modifier.fillMaxWidth().padding(top = 6.dp)) {
                                HydraChoiceButton(networkRuleSubTab == 0, "IP'S", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { networkRuleSubTab = 0 }, modifier = Modifier.height(30.dp))
                                Spacer(Modifier.width(8.dp))
                                HydraChoiceButton(networkRuleSubTab == 1, "PUERTOS", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { networkRuleSubTab = 1 }, modifier = Modifier.height(30.dp))
                            }
                            when (networkRuleSubTab) {
                                0 -> IpRulesPanel(context, language == AppLanguage.EN, ipBlockStore, ipVersion, { ipVersion++; notifyRulesChanged(context) })
                                else -> PortRulesPanel(context, language == AppLanguage.EN, apps, advancedRuleStore, advancedVersion, { advancedVersion++; notifyRulesChanged(context) })
                            }
                        }
                    }
                    MainTab.CONNECTIONS -> {
                        // Read the version state here so an IP rule change immediately
                        // recomposes the connection list and refreshes BLOCKED/BLOCK IP UI.
                        val currentIpVersion = ipVersion
                        var selectedHistoryDetail by remember { mutableStateOf<ConnectionHistory.Record?>(null) }
                        Column(Modifier.fillMaxSize().padding(10.dp)) {
                            Text(tr(context,"history"), style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    HydraChoiceButton(groupedHistory, if (language == AppLanguage.EN) "Grouped" else "Agrupado", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { groupedHistory = true }, modifier = Modifier.height(30.dp))
                                    Spacer(Modifier.width(6.dp))
                                    HydraChoiceButton(!groupedHistory, if (language == AppLanguage.EN) "Detail" else "Detalle", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { groupedHistory = false }, modifier = Modifier.height(30.dp))
                                }
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    TextButton({ ConnectionHistory.clear(); history = emptyList() }) { Text(tr(context,"clear")) }
                                }
                            }
                            if (!groupedHistory) {
                                Box {
                                    TextButton({ historySortMenu = true }) { Text("${tr(context,"order")}: ${historySortLabel(context, historySort)}") }
                                    DropdownMenu(expanded = historySortMenu, onDismissRequest = { historySortMenu = false }) {
                                        HistorySort.values().forEach { sort -> DropdownMenuItem(text = { Text(historySortLabel(context, sort)) }, onClick = { historySort = sort; historySortMenu = false }) }
                                    }
                                }
                            }
                            val sortedHistory = when (historySort) {
                                HistorySort.TIME -> history.sortedByDescending { it.timestamp }
                                HistorySort.APP -> history.sortedWith(compareBy<ConnectionHistory.Record> { record -> record.packageName ?: "~UID ${record.uid}" }.thenByDescending { record -> record.timestamp })
                                HistorySort.IP -> history.sortedWith(compareBy<ConnectionHistory.Record> { record -> extractHost(record.destination) }.thenByDescending { record -> record.timestamp })
                                HistorySort.PORT -> history.sortedWith(compareBy<ConnectionHistory.Record> { record -> extractPort(record.destination) }.thenByDescending { record -> record.timestamp })
                            }
                            if (groupedHistory) {
                                val groups = history.groupBy { "${it.packageName ?: "UID ${it.uid}"}|${it.protocol}|${it.destination}" }.values
                                    .map { items ->
                                        val first = items.maxByOrNull { it.timestamp }!!
                                        HistoryGroup(
                                            first,
                                            items.sumOf { it.repeatCount },
                                            items.filter { it.allowed }.sumOf { it.repeatCount },
                                            items.filter { !it.allowed }.sumOf { it.repeatCount }
                                        )
                                    }
                                    .sortedByDescending { it.last.timestamp }
                                LazyColumn(Modifier.weight(1f)) {
                                    items(groups, key = { "${it.last.id}:${it.count}:$currentIpVersion" }) { g ->
                                        val host = extractHost(g.last.destination)
                                        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                                            Text(g.last.packageName ?: "UID ${g.last.uid}", style = MaterialTheme.typography.titleSmall)
                                            Text("${g.last.protocol} • ${g.last.destination}", fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                            Text("${g.count} eventos • ${if (language == AppLanguage.EN) "allowed" else "permitidos"}: ${g.allowed} • ${if (language == AppLanguage.EN) "blocked" else "bloqueados"}: ${g.blocked}", style = MaterialTheme.typography.bodySmall)
                                            Text(g.last.time, style = MaterialTheme.typography.labelSmall)
                                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                                TextButton({ selectedHistoryDetail = g.last }) { Text(if (language == AppLanguage.EN) "Details" else "Detalles") }
                                                val groupedIpBlocked = host.isNotBlank() && ipBlockStore.isBlocked(host)
                                                val groupedIpException = host.isNotBlank() && ipBlockStore.isAllowedForUid(g.last.uid, host)
                                                val groupedHasBlockedEvents = g.blocked > 0
                                                val groupedAction = when {
                                                    groupedIpBlocked -> if (language == AppLanguage.EN) "UNBLOCK IP" else "DESBLOQUEAR IP"
                                                    groupedIpException -> if (language == AppLanguage.EN) "REMOVE IP ALLOW" else "QUITAR PERMISO IP"
                                                    groupedHasBlockedEvents -> if (language == AppLanguage.EN) "ALLOW IP" else "PERMITIR IP"
                                                    else -> if (language == AppLanguage.EN) "BLOCK IP" else "BLOQUEAR IP"
                                                }
                                                Button(
                                                    onClick = {
                                                        if (host.isNotBlank()) {
                                                            when {
                                                                groupedIpBlocked -> ipBlockStore.remove(host)
                                                                groupedIpException -> ipBlockStore.removeAllowedForUid(g.last.uid, host)
                                                                groupedHasBlockedEvents -> ipBlockStore.allowForUid(g.last.uid, host)
                                                                else -> ipBlockStore.add(host)
                                                            }
                                                            notifyRulesChanged(context)
                                                            ipVersion++
                                                        }
                                                    },
                                                    modifier = Modifier.height(29.dp),
                                                    elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp, pressedElevation = 0.dp, focusedElevation = 0.dp, hoveredElevation = 0.dp, disabledElevation = 0.dp),
                                                    colors = ButtonDefaults.buttonColors(
                                                        containerColor = when {
                                                            groupedIpBlocked -> Color(0xFF632B34)
                                                            groupedIpException -> Color(0xFFD5F5E3)
                                                            groupedHasBlockedEvents -> Color(0xFFFFE6A8)
                                                            else -> MaterialTheme.colorScheme.surfaceVariant
                                                        },
                                                        contentColor = when {
                                                            groupedIpBlocked -> Color(0xFFFFDAD6)
                                                            groupedIpException -> Color(0xFF145A32)
                                                            groupedHasBlockedEvents -> Color(0xFF6B4E00)
                                                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                                                        }
                                                    ),
                                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                                                ) { Text(groupedAction, fontSize = 10.sp) }
                                            }
                                        }
                                        HorizontalDivider()
                                    }
                                }
                            } else {
                                LazyColumn(Modifier.weight(1f)) {
                                    items(sortedHistory, key = { it.id }) { item ->
                                        val host = extractHost(item.destination)
                                        val domain = DomainResolver.cached(host)
                                        val isBlocked = ipBlockStore.isBlocked(host)
                                        Column(Modifier.fillMaxWidth().padding(vertical = 7.dp)) {
                                            Text("${item.time}  ${item.packageName ?: "UID ${item.uid}"}", style = MaterialTheme.typography.titleSmall)
                                            Text("${item.protocol} • ${item.network.displayName} • ${if (item.allowed) tr(context,"allow") else tr(context,"block")}", style = MaterialTheme.typography.bodySmall)
                                            Text("${item.source} → ${item.destination}", fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                            Text("Dominio: ${domain ?: tr(context,"domain_unavailable")}", style = MaterialTheme.typography.bodySmall)
                                            if (item.repeatCount > 1) {
                                                Text(
                                                    if (language == AppLanguage.EN) "Repeated attempts: ${item.repeatCount}" else "Intentos repetidos: ${item.repeatCount}",
                                                    style = MaterialTheme.typography.bodySmall
                                                )
                                            }
                                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                                TextButton({ selectedHistoryDetail = item }) { Text(if (language == AppLanguage.EN) "Details" else "Detalles") }
                                                val ipException = host.isNotBlank() && ipBlockStore.isAllowedForUid(item.uid, host)
                                                val hasBlockedEvent = !item.allowed
                                                val ipAction = when {
                                                    isBlocked -> if (language == AppLanguage.EN) "UNBLOCK IP" else "DESBLOQUEAR IP"
                                                    ipException -> if (language == AppLanguage.EN) "REMOVE IP ALLOW" else "QUITAR PERMISO IP"
                                                    hasBlockedEvent -> if (language == AppLanguage.EN) "ALLOW IP" else "PERMITIR IP"
                                                    else -> if (language == AppLanguage.EN) "BLOCK IP" else "BLOQUEAR IP"
                                                }
                                                Button(
                                                    onClick = {
                                                        if (host.isNotBlank()) {
                                                            when {
                                                                isBlocked -> ipBlockStore.remove(host)
                                                                ipException -> ipBlockStore.removeAllowedForUid(item.uid, host)
                                                                hasBlockedEvent -> ipBlockStore.allowForUid(item.uid, host)
                                                                else -> ipBlockStore.add(host)
                                                            }
                                                            notifyRulesChanged(context)
                                                            ipVersion++
                                                        }
                                                    },
                                                    modifier = Modifier.height(29.dp),
                                                    elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp, pressedElevation = 0.dp, focusedElevation = 0.dp, hoveredElevation = 0.dp, disabledElevation = 0.dp),
                                                    colors = ButtonDefaults.buttonColors(
                                                        containerColor = when {
                                                            isBlocked -> Color(0xFF632B34)
                                                            ipException -> Color(0xFFD5F5E3)
                                                            hasBlockedEvent -> Color(0xFFFFE6A8)
                                                            else -> MaterialTheme.colorScheme.surfaceVariant
                                                        },
                                                        contentColor = when {
                                                            isBlocked -> Color(0xFFFFDAD6)
                                                            ipException -> Color(0xFF145A32)
                                                            hasBlockedEvent -> Color(0xFF6B4E00)
                                                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                                                        }
                                                    ),
                                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                                                ) { Text(ipAction, fontSize = 10.sp) }
                                                if (isBlocked) {
                                                    TextButton({ ipBlockStore.remove(host); notifyRulesChanged(context); ipVersion++ }) { Text(if (language == AppLanguage.EN) "UNBLOCK" else "DESBLOQUEAR") }
                                                }
                                            }
                                        }
                                        HorizontalDivider()
                                    }
                                }
                            }
                        }
                        selectedHistoryDetail?.let { record ->
                            val host = extractHost(record.destination)
                            val port = extractPort(record.destination)
                            val matches = advancedRuleStore.findMatches(record.uid, record.protocol, port)
                            val isIpBlocked = host.isNotBlank() && ipBlockStore.isBlocked(host)
                            AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
                                onDismissRequest = { selectedHistoryDetail = null },
                                title = { Text(if (language == AppLanguage.EN) "Connection details" else "Detalles de conexión", color = hydraDialogColors().second) },
                                text = {
                                    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                                        Text("${record.packageName ?: "UID ${record.uid}"}", style = MaterialTheme.typography.titleSmall)
                                        Text("${record.protocol} • ${record.destination}", fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                        Text("${if (record.allowed) (if (language == AppLanguage.EN) "Allowed" else "Permitido") else (if (language == AppLanguage.EN) "Blocked" else "Bloqueado")}", style = MaterialTheme.typography.bodySmall)
                                        if (record.repeatCount > 1) {
                                            Text(
                                                if (language == AppLanguage.EN) "Repeated attempts: ${record.repeatCount}" else "Intentos repetidos: ${record.repeatCount}",
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                        Text(
                                            if (record.allowed) {
                                                if (language == AppLanguage.EN) "Reason: allowed by current policy" else "Motivo: permitido por la política actual"
                                            } else {
                                                if (isIpBlocked) "${if (language == AppLanguage.EN) "Reason: IP block" else "Motivo: bloqueo IP"}"
                                                else if (matches.any { !it.allowed }) "${if (language == AppLanguage.EN) "Reason: port rule" else "Motivo: regla de puerto"}"
                                                else if (ruleStore.getSchedule(record.uid).enabled && RuleEngine(ruleStore, context).isScheduleBlocked(record.uid)) "${if (language == AppLanguage.EN) "Reason: schedule" else "Motivo: horario"}"
                                                else if (!ruleStore.allowLocalNetwork && host.isNotBlank()) "${if (language == AppLanguage.EN) "Reason: local-network policy" else "Motivo: política de red local"}"
                                                else "${if (language == AppLanguage.EN) "Reason: application/network rule" else "Motivo: regla de aplicación/red"}"
                                            },
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                        val isIpException = host.isNotBlank() && ipBlockStore.isAllowedForUid(record.uid, host)
                                        Text(
                                            if (language == AppLanguage.EN) {
                                                "IP rule: ${when { isIpBlocked -> "BLOCKED"; isIpException -> "ALLOWED FOR THIS UID"; else -> "not blocked" }}"
                                            } else {
                                                "Regla IP: ${when { isIpBlocked -> "BLOQUEADA"; isIpException -> "PERMITIDA PARA ESTE UID"; else -> "no bloqueada" }}"
                                            },
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                        Spacer(Modifier.height(5.dp))
                                        val whyReasons = remember(record.id) {
                                            ConnectionContext.explain(
                                                context, record.uid, record.packageName, record.destination, record.protocol,
                                                allowed = record.allowed, firstConnection = record.event == "FIRST-SEEN", repeatCount = record.repeatCount
                                            )
                                        }
                                        ConnectionWhyBlock(whyReasons, language == AppLanguage.EN)
                                        Spacer(Modifier.height(5.dp))
                                        Text(if (language == AppLanguage.EN) "Matching port rules" else "Reglas de puerto coincidentes", style = MaterialTheme.typography.titleSmall)
                                        if (matches.isEmpty()) {
                                            Text(if (language == AppLanguage.EN) "No explicit port rule matches this connection." else "No hay una regla de puerto explícita que coincida con esta conexión.", style = MaterialTheme.typography.bodySmall)
                                        } else {
                                            matches.forEach { rule ->
                                                Card(Modifier.fillMaxWidth()) {
                                                    Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                                        Column(Modifier.weight(1f)) {
                                                            Text("${rule.protocol} ${rule.startPort}${if (rule.endPort != rule.startPort) "-${rule.endPort}" else ""}", fontFamily = FontFamily.Monospace)
                                                            Text(if (rule.allowed) (if (language == AppLanguage.EN) "ALLOW" else "PERMITIR") else (if (language == AppLanguage.EN) "BLOCK" else "BLOQUEAR"), style = MaterialTheme.typography.bodySmall)
                                                        }
                                                        TextButton({ advancedRuleStore.remove(rule); advancedVersion++; notifyRulesChanged(context); selectedHistoryDetail = record }) { Text(if (language == AppLanguage.EN) "Delete" else "Eliminar") }
                                                    }
                                                }
                                            }
                                        }
                                        Spacer(Modifier.height(4.dp))
                                        when {
                                            isIpBlocked -> TextButton({ ipBlockStore.remove(host); ipVersion++; notifyRulesChanged(context); selectedHistoryDetail = record }) { Text(if (language == AppLanguage.EN) "Unblock IP" else "Desbloquear IP") }
                                            isIpException -> TextButton({ ipBlockStore.removeAllowedForUid(record.uid, host); ipVersion++; notifyRulesChanged(context); selectedHistoryDetail = record }) { Text(if (language == AppLanguage.EN) "Remove IP allow" else "Quitar permiso IP") }
                                            !record.allowed -> TextButton({ ipBlockStore.allowForUid(record.uid, host); ipVersion++; notifyRulesChanged(context); selectedHistoryDetail = record }) { Text(if (language == AppLanguage.EN) "Allow this IP for this app" else "Permitir esta IP para esta app") }
                                            else -> TextButton({ ipBlockStore.add(host); ipVersion++; notifyRulesChanged(context); selectedHistoryDetail = record }) { Text(if (language == AppLanguage.EN) "Block IP" else "Bloquear IP") }
                                        }
                                    }
                                },
                                confirmButton = { TextButton({ selectedHistoryDetail = null }) { Text(tr(context,"close")) } }
                            )
                        }
                    }
                    MainTab.ANALYZER -> {
                        TrafficAnalyzerScreen(context)
                    }
                    MainTab.STATS -> {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().padding(horizontal = 10.dp),
                            contentPadding = PaddingValues(bottom = 24.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            item {
                                Text(tr(context,"live_traffic"), style = MaterialTheme.typography.titleMedium)
                                LiveTrafficChart(trafficHistory)
                                TrafficTotalsBarChart(trafficTotals.allowedBytes, trafficTotals.blockedBytes)
                                Spacer(Modifier.height(6.dp))
                                Card(Modifier.fillMaxWidth()) {
                                    Column(Modifier.fillMaxWidth().padding(12.dp)) {
                                        Text(
                                            if (language == AppLanguage.EN) "Ads / tracker blocks today" else "Bloqueos de anuncios / rastreadores hoy",
                                            style = MaterialTheme.typography.titleSmall
                                        )
                                        Text(
                                            blockAdsBlockedToday.toString(),
                                            style = MaterialTheme.typography.headlineSmall,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Text(
                                            if (language == AppLanguage.EN)
                                                "Blocklist matches intercepted by DNS and HTTPS/SNI. The list also includes malware domains."
                                            else
                                                "Coincidencias de la blocklist interceptadas por DNS y HTTPS/SNI. La lista también incluye dominios de malware.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                                HorizontalDivider()
                            }
                            item {
                                HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                    Text(tr(context,"consumption"), style = MaterialTheme.typography.titleMedium)
                                    TextButton({ TrafficStatsStore.clear(); stats = emptyList(); trafficTotals = TrafficStatsStore.totals(); trafficHistory = listOf(0f to 0f) }) { Text(tr(context,"clear")) }
                                }
                                TrafficUsageChart(stats)
                            }
                            item {
                                AppUsageCard(language == AppLanguage.EN, stats)
                                HorizontalDivider()
                            }
                            item {
                                val daily = DailyTrafficStore.lastDays(7)
                                val protocolSummary = history.groupingBy { it.protocol.uppercase() }.eachCount()
                                val networkSummary = history.groupingBy { it.network.displayName }.eachCount()
                                val ipv4Count = history.count { !extractHost(it.destination).contains(":") }
                                val ipv6Count = history.count { extractHost(it.destination).contains(":") }
                                Text(if (language == AppLanguage.EN) "Today" else "Hoy", style = MaterialTheme.typography.titleSmall)
                                val today = daily.firstOrNull()
                                Text(if (language == AppLanguage.EN) "Allowed ${formatBytes(today?.allowed ?: trafficTotals.allowedBytes)} · Blocked ${formatBytes(today?.blocked ?: trafficTotals.blockedBytes)}" else "Permitido ${formatBytes(today?.allowed ?: trafficTotals.allowedBytes)} · Bloqueado ${formatBytes(today?.blocked ?: trafficTotals.blockedBytes)}", style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(4.dp))
                                HydraHorizontalRow(Modifier.fillMaxWidth().height(34.dp)) {
                                    AssistChip(onClick = {}, label = { Text("IPv4 $ipv4Count") }); Spacer(Modifier.width(5.dp))
                                    AssistChip(onClick = {}, label = { Text("IPv6 $ipv6Count") }); Spacer(Modifier.width(5.dp))
                                    protocolSummary.entries.sortedByDescending { it.value }.take(4).forEach { (proto,count) -> AssistChip(onClick = {}, label = { Text("$proto $count") }); Spacer(Modifier.width(5.dp)) }
                                    networkSummary.entries.sortedByDescending { it.value }.take(2).forEach { (net,count) -> AssistChip(onClick = {}, label = { Text("$net $count") }); Spacer(Modifier.width(5.dp)) }
                                }
                            }
                            item {
                                val daily = DailyTrafficStore.lastDays(7)
                                Text(if (language == AppLanguage.EN) "Last 7 days" else "Últimos 7 días", style = MaterialTheme.typography.titleSmall)
                                daily.forEach { day ->
                                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text(day.key, style = MaterialTheme.typography.labelSmall)
                                        Text("↑ ${formatBytes(day.allowed)}  ↓ ${formatBytes(day.blocked)}", style = MaterialTheme.typography.labelSmall)
                                    }
                                }
                            }
                            item {
                                val destinationSummary = history.groupBy { it.destination }
                                    .map { (destination, records) -> destination to records.size }
                                    .sortedByDescending { it.second }
                                    .take(8)
                                if (learningMode && destinationSummary.isNotEmpty()) {
                                    Text(if (language == AppLanguage.EN) "Learning suggestions" else "Sugerencias de aprendizaje", style = MaterialTheme.typography.titleSmall)
                                    Text(if (language == AppLanguage.EN) "Review these frequent destinations before creating permanent IP or port rules." else "Revisá estos destinos frecuentes antes de crear reglas IP o de puertos permanentes.", style = MaterialTheme.typography.bodySmall)
                                }
                                if (destinationSummary.isNotEmpty()) {
                                    Text(if (language == AppLanguage.EN) "Most active destinations" else "Destinos más activos", style = MaterialTheme.typography.titleSmall)
                                    destinationSummary.forEach { (destination, count) ->
                                        Row(Modifier.fillMaxWidth().heightIn(min = 70.dp).padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("${serviceLabel(destination)}  $destination", fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
                                            Text("$count", style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                }
                            }
                            item {
                                val portSummary = history.groupBy { extractPort(it.destination) }.filterKeys { it >= 0 }.map { (port,count) -> port to count.size }.sortedByDescending { it.second }.take(8)
                                if (portSummary.isNotEmpty()) {
                                    Text(if (language == AppLanguage.EN) "Most used ports" else "Puertos más usados", style=MaterialTheme.typography.titleSmall)
                                    portSummary.forEach { (port,count) -> Row(Modifier.fillMaxWidth().padding(vertical=2.dp), horizontalArrangement=Arrangement.SpaceBetween) { Text("${serviceLabelForPort(port)}  $port", fontFamily=FontFamily.Monospace, fontSize=11.sp); Text(count.toString(), style=MaterialTheme.typography.labelSmall) } }
                                }
                            }
                            items(stats, key = { it.uid }) { s ->
                                Card(Modifier.fillMaxWidth()) {
                                    Column(Modifier.fillMaxWidth().padding(10.dp)) {
                                        Text(s.packageName ?: "UID ${s.uid}", style = MaterialTheme.typography.titleSmall)
                                        Text("${tr(context,"connections_word")}: ${s.connections} • ${tr(context,"blocked_word")}: ${s.blocked}", style = MaterialTheme.typography.bodySmall)
                                        Text("↑ ${formatBytes(s.txBytes)}  ↓ ${formatBytes(s.rxBytes)}", style = MaterialTheme.typography.bodySmall)
                                        Text("Bloqueado: ${formatBytes(s.blockedBytes)}", style = MaterialTheme.typography.labelSmall)
                                    }
                                }
                            }
                        }
                    }
                    MainTab.PROFILES -> {
                        var selectedProfileForDetails by remember { mutableStateOf<String?>(null) }
                        key(ruleVersion, advancedVersion, profileVersion) {
                        val currentSnapshot = exportRuleSnapshot(ruleStore, advancedRuleStore)
                        val names = profilesStore.names()
                        val loadedProfileName = names.firstOrNull { profilesStore.load(it) == currentSnapshot }
                        val currentSummary = runCatching { profileSummary(currentSnapshot) { uid -> apps.firstOrNull { a -> a.uid == uid }?.label ?: "UID $uid" } }.getOrNull()
                        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp)) {
                            Text(if (language == AppLanguage.EN) "Profiles" else "Perfiles", style = MaterialTheme.typography.titleMedium)
                            Text(if (language == AppLanguage.EN) "Save and restore the complete firewall configuration. Each profile shows what it will allow and block." else "Guardá y restaurá la configuración completa. Cada perfil muestra qué va a permitir y bloquear.", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                OutlinedTextField(profileName, { profileName = it }, Modifier.weight(1f), singleLine = true, label = { Text(if (language == AppLanguage.EN) "Profile name" else "Nombre del perfil") })
                                Spacer(Modifier.width(8.dp))
                                Button({ val n=profileName.trim(); if(n.isNotEmpty()){ profilesStore.save(n, exportRuleSnapshot(ruleStore, advancedRuleStore)); profileName=""; profileVersion++ } }) { Text(if (language == AppLanguage.EN) "Save" else "Guardar") }
                            }
                            Spacer(Modifier.height(10.dp))
                            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                                Column(Modifier.fillMaxWidth().padding(10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Box(Modifier.size(10.dp).background(if (loadedProfileName != null) Color(0xFF2E7D32) else Color(0xFFD32F2F), CircleShape))
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            if (loadedProfileName != null) {
                                                if (language == AppLanguage.EN) "Loaded profile: $loadedProfileName" else "Perfil cargado: $loadedProfileName"
                                            } else {
                                                if (language == AppLanguage.EN) "Current configuration — not saved in a profile" else "Configuración actual — no guardada en un perfil"
                                            },
                                            style = MaterialTheme.typography.titleSmall
                                        )
                                    }
                                    if (currentSummary != null) {
                                        Text(
                                            if (language == AppLanguage.EN) "Apps ${currentSummary.appRuleCount} • Wi-Fi blocked ${currentSummary.wifiBlockedCount} • Mobile blocked ${currentSummary.mobileBlockedCount} • Schedules ${currentSummary.scheduleCount} • Advanced ${currentSummary.advancedRuleCount}"
                                            else "Apps ${currentSummary.appRuleCount} • Wi-Fi bloqueadas ${currentSummary.wifiBlockedCount} • Móvil bloqueadas ${currentSummary.mobileBlockedCount} • Horarios ${currentSummary.scheduleCount} • Avanzadas ${currentSummary.advancedRuleCount}",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                        OutlinedButton({
                                            resetRulesToDefaults(ruleStore, advancedRuleStore, ipBlockStore)
                                            ruleVersion++
                                            advancedVersion++
                                            profileVersion++
                                            notifyRulesChanged(context)
                                        }) { Text(if (language == AppLanguage.EN) "Reset rules" else "Restablecer reglas") }
                                    }
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            if (names.isEmpty()) {
                                Text(if (language == AppLanguage.EN) "No saved profiles yet." else "Todavía no hay perfiles guardados.", style=MaterialTheme.typography.bodySmall)
                            } else {
                                names.forEach { name ->
                                    val snapshot = profilesStore.load(name)
                                    val summary = snapshot?.let { runCatching { profileSummary(it) { uid -> apps.firstOrNull { a -> a.uid == uid }?.label ?: "UID $uid" } }.getOrNull() }
                                    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                                        Column(Modifier.fillMaxWidth().padding(10.dp)) {
                                            val isLoaded = snapshot != null && snapshot == currentSnapshot
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Box(Modifier.size(10.dp).background(if (isLoaded) Color(0xFF2E7D32) else Color(0xFFD32F2F), CircleShape))
                                                Spacer(Modifier.width(8.dp))
                                                Text(name, style = MaterialTheme.typography.titleSmall)
                                                if (isLoaded) {
                                                    Spacer(Modifier.width(6.dp))
                                                    Text(if(language==AppLanguage.EN) "LOADED" else "CARGADO", style=MaterialTheme.typography.labelSmall)
                                                }
                                            }
                                            if (summary != null) {
                                                Text("${if(language==AppLanguage.EN) "Policy" else "Política"}: ${summary.policyMode}", style=MaterialTheme.typography.bodySmall)
                                                Text(if(language==AppLanguage.EN) "Apps ${summary.appRuleCount} • Wi-Fi blocked ${summary.wifiBlockedCount} • Mobile blocked ${summary.mobileBlockedCount} • Schedules ${summary.scheduleCount}" else "Apps ${summary.appRuleCount} • Wi-Fi bloqueadas ${summary.wifiBlockedCount} • Móvil bloqueadas ${summary.mobileBlockedCount} • Horarios ${summary.scheduleCount}", style=MaterialTheme.typography.bodySmall)
                                                Text(if(language==AppLanguage.EN) "Advanced ${summary.advancedRuleCount}: ${summary.advancedBlockCount} block / ${summary.advancedAllowCount} allow" else "Avanzadas ${summary.advancedRuleCount}: ${summary.advancedBlockCount} bloqueadas / ${summary.advancedAllowCount} permitidas", style=MaterialTheme.typography.bodySmall)
                                            }
                                            Row(Modifier.fillMaxWidth(), horizontalArrangement=Arrangement.End) {
                                                TextButton({ selectedProfileForDetails=name }) { Text(if(language==AppLanguage.EN) "Details" else "Detalles") }
                                                TextButton({ snapshot?.let { runCatching { importRuleSnapshot(ruleStore, advancedRuleStore, it); ruleVersion++; advancedVersion++; notifyRulesChanged(context) } } }) { Text(if(language==AppLanguage.EN) "Apply" else "Aplicar") }
                                                TextButton({ profilesStore.delete(name); profileVersion++ }) { Text(tr(context,"remove")) }
                                            }
                                        }
                                    }
                                }
                            }
                            Spacer(Modifier.height(12.dp))
                            ConfigTransferCard(context, language == AppLanguage.EN) {
                                ruleVersion++; advancedVersion++; profileVersion++; ipVersion++; refreshTrigger++
                            }
                        }
                        selectedProfileForDetails?.let { name ->
                            val snapshot = profilesStore.load(name)
                            val summary = snapshot?.let { runCatching { profileSummary(it) { uid -> apps.firstOrNull { a -> a.uid == uid }?.label ?: "UID $uid" } }.getOrNull() }
                            if (summary != null) AlertDialog(
                                onDismissRequest={selectedProfileForDetails=null},
                                title={Text(name)},
                                text={
                                    Column(Modifier.verticalScroll(rememberScrollState())) {
                                        Text("${if(language==AppLanguage.EN) "Policy" else "Política"}: ${summary.policyMode}")
                                        Text(if(language==AppLanguage.EN) "Default Wi-Fi: ${if(summary.defaultWifiAllowed) "ALLOW" else "BLOCK"}" else "Wi-Fi predeterminado: ${if(summary.defaultWifiAllowed) "PERMITIR" else "BLOQUEAR"}")
                                        Text(if(language==AppLanguage.EN) "Default mobile: ${if(summary.defaultMobileAllowed) "ALLOW" else "BLOCK"}" else "Móvil predeterminado: ${if(summary.defaultMobileAllowed) "PERMITIR" else "BLOQUEAR"}")
                                        Spacer(Modifier.height(8.dp))
                                        Text(if(language==AppLanguage.EN) "Per-app rules" else "Reglas por aplicación", style=MaterialTheme.typography.titleSmall)
                                        Text(if(language==AppLanguage.EN) "${summary.appRuleCount} app rules • ${summary.wifiBlockedCount} Wi-Fi blocked • ${summary.mobileBlockedCount} mobile blocked • ${summary.scheduleCount} schedules" else "${summary.appRuleCount} reglas de apps • ${summary.wifiBlockedCount} Wi-Fi bloqueadas • ${summary.mobileBlockedCount} móvil bloqueadas • ${summary.scheduleCount} horarios")
                                        Spacer(Modifier.height(8.dp))
                                        Text(if(language==AppLanguage.EN) "Advanced rules" else "Reglas avanzadas", style=MaterialTheme.typography.titleSmall)
                                        if(summary.advancedRules.isEmpty()) Text(if(language==AppLanguage.EN) "None" else "Ninguna")
                                        else summary.advancedRules.forEach { (appName, protoPort, action) -> Text("• $appName • $protoPort • $action", fontFamily=FontFamily.Monospace, fontSize=11.sp) }
                                    }
                                },
                                confirmButton={TextButton({selectedProfileForDetails=null}){Text(tr(context,"close"))}}
                            )
                        }
                        }
                    }
                    MainTab.SECURITY -> {
                        SecurityCenterTab(context, language)
                    }
                    MainTab.SELFTEST -> {
                        SelfTestScreen(context, language)
                    }
                    MainTab.HELP -> {
                        HelpScreen(context, language)
                    }
                    MainTab.ABOUT -> {
                        AboutScreen(context)
                    }
                    MainTab.SETTINGS -> {
                        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 10.dp)) {
                            Text("Firewall", style = MaterialTheme.typography.titleSmall)
                            Text(if (language == AppLanguage.EN) "Global mode" else "Modo global", style = MaterialTheme.typography.labelLarge)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                HydraChoiceButton(globalMode == GlobalMode.BLACKLIST, tr(context,"blacklist"), Color(0xFFF1D0D0), Color(0xFF5A1D22), onClick = { globalMode = GlobalMode.BLACKLIST; defaultWifi = false; defaultMobile = false; ruleStore.policyMode = GlobalMode.BLACKLIST.name; ruleStore.defaultWifiAllowed = false; ruleStore.defaultMobileAllowed = false; notifyRulesChanged(context) }, modifier = Modifier.height(30.dp))
                                Spacer(Modifier.width(8.dp))
                                HydraChoiceButton(globalMode == GlobalMode.WHITELIST, tr(context,"whitelist"), Color(0xFFD7E9F9), Color(0xFF173A5E), onClick = { globalMode = GlobalMode.WHITELIST; defaultWifi = true; defaultMobile = true; ruleStore.policyMode = GlobalMode.WHITELIST.name; ruleStore.defaultWifiAllowed = true; ruleStore.defaultMobileAllowed = true; notifyRulesChanged(context) }, modifier = Modifier.height(30.dp))
                            }
                            Text(if (globalMode == GlobalMode.BLACKLIST) tr(context,"blacklist_sub") else tr(context,"whitelist_sub"), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 3.dp))
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) { Text(if (language == AppLanguage.EN) "← swipe for full text" else "← deslizá para leer completo", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                            Spacer(Modifier.height(10.dp))
                            AllowBlockRow(
                                tr(context,"default_wifi"),
                                defaultWifi,
                                tr(context,"default_rule_info"),
                                tr(context,"default_prompt_info"),
                            ) {
                                defaultWifi = it
                                ruleStore.defaultWifiAllowed = it
                            }
                            AllowBlockRow(
                                tr(context,"default_mobile"),
                                defaultMobile,
                                tr(context,"default_rule_info"),
                                tr(context,"default_prompt_info"),
                            ) {
                                defaultMobile = it
                                ruleStore.defaultMobileAllowed = it
                            }
                            Spacer(Modifier.height(10.dp))
                            SettingSwitchRow(tr(context,"ask_first"), tr(context,"ask_first_sub"), askFirst) { askFirst=it; ruleStore.askOnFirstConnection=it; notifyRulesChanged(context) }
                            SettingSwitchRow(
                                if (language == AppLanguage.EN) "Learning analysis" else "Análisis de aprendizaje",
                                if (language == AppLanguage.EN) "Analysis only: builds traffic suggestions without changing firewall decisions." else "Solo análisis: genera sugerencias de tráfico sin cambiar las decisiones del firewall.",
                                learningMode
                            ) { learningMode = it; ruleStore.learningMode = it }
                            SettingSwitchRow(tr(context,"allow_unknown"), tr(context,"allow_unknown_sub"), invalidAllowed) { invalidAllowed=it; ruleStore.invalidUidAllowed=it; notifyRulesChanged(context) }
                            SettingSwitchRow(tr(context,"allow_local"), tr(context,"allow_local_sub"), allowLocal) { allowLocal=it; ruleStore.allowLocalNetwork=it; notifyRulesChanged(context) }
                            SettingSwitchRow(tr(context,"advanced_mode"), tr(context,"advanced_mode_sub"), advancedMode) { advancedMode=it; settingsStore.advancedMode=it }
                            SettingSwitchRow(tr(context,"block_ipv6"), tr(context,"block_ipv6_sub"), blockIpv6) { blockIpv6=it; ruleStore.blockIpv6=it; notifyRulesChanged(context) }
                            SettingSwitchRow(tr(context,"block_roaming"), tr(context,"block_roaming_sub"), blockRoaming) { blockRoaming=it; ruleStore.blockWhenRoaming=it; notifyRulesChanged(context) }
                            SettingSwitchRow(tr(context,"block_screen"), tr(context,"block_screen_sub"), blockScreenOff) { blockScreenOff=it; ruleStore.blockWhenScreenOff=it; notifyRulesChanged(context) }

                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(if (language == AppLanguage.EN) "Secure DNS" else "DNS seguro", style = MaterialTheme.typography.titleMedium)
                            Text(
                                if (language == AppLanguage.EN)
                                    "Advanced encrypted DNS configuration. Secure DNS is applied through the Hydra VPN when enabled."
                                else
                                    "Configuración avanzada de DNS cifrado. El DNS seguro se aplica mediante la VPN de Hydra cuando está habilitado.",
                                style = MaterialTheme.typography.bodySmall
                            )
                            SettingSwitchRow(
                                tr(context, "secure_dns"),
                                tr(context, "secure_dns_sub"),
                                secureDns
                            ) { enabled ->
                                secureDns = enabled
                                ruleStore.secureDnsEnabled = enabled
                                notifyRulesChanged(context)
                            }
                            if (secureDns) {
                                DnsProviderSection(
                                    context = context,
                                    english = language == AppLanguage.EN,
                                    transport = dnsTransport,
                                    onTransportChange = { transport ->
                                        dnsTransport = transport
                                        ruleStore.dnsTransport = transport
                                        notifyRulesChanged(context)
                                    },
                                    provider = dnsProvider,
                                    customIpv4 = customDnsIpv4,
                                    customIpv6 = customDnsIpv6,
                                    customHostname = customDnsHostname,
                                    customDohUrl = customDnsDohUrl,
                                    onProviderChange = { provider ->
                                        dnsProvider = provider
                                        ruleStore.dnsProvider = provider
                                        notifyRulesChanged(context)
                                    },
                                    onCustomIpv4Change = { value ->
                                        customDnsIpv4 = value
                                        ruleStore.customDnsIpv4 = value
                                        notifyRulesChanged(context)
                                    },
                                    onCustomIpv6Change = { value ->
                                        customDnsIpv6 = value
                                        ruleStore.customDnsIpv6 = value
                                        notifyRulesChanged(context)
                                    },
                                    onCustomHostnameChange = { value ->
                                        customDnsHostname = value
                                        ruleStore.customDnsHostname = value
                                        notifyRulesChanged(context)
                                    },
                                    onCustomDohUrlChange = { value ->
                                        customDnsDohUrl = value
                                        ruleStore.customDnsDohUrl = value
                                        notifyRulesChanged(context)
                                    }
                                )
                            }

                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(if (language == AppLanguage.EN) "Performance & battery" else "Rendimiento y batería", style = MaterialTheme.typography.titleMedium)
                            SettingSwitchRow(
                                if (language == AppLanguage.EN) "Low-power mode" else "Modo bajo consumo",
                                if (language == AppLanguage.EN) "Slows non-essential UI updates and foreground status refreshes without changing filtering." else "Reduce las actualizaciones no esenciales de la interfaz y del estado sin cambiar el filtrado.",
                                lowPowerMode
                            ) { lowPowerMode = it; appSettings.lowPowerMode = it }
                            SettingSwitchRow(
                                if (language == AppLanguage.EN) "Pause UI while screen is off" else "Pausar interfaz con pantalla apagada",
                                if (language == AppLanguage.EN) "Stops visual refresh work while the display is off; the VPN and rules keep running." else "Detiene el trabajo visual mientras la pantalla está apagada; la VPN y las reglas siguen funcionando.",
                                pauseUiScreenOff
                            ) { pauseUiScreenOff = it; appSettings.pauseUiWhenScreenOff = it }
                            Text(if (language == AppLanguage.EN) "UI refresh" else "Actualización de interfaz", style = MaterialTheme.typography.bodyMedium)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                listOf(1,2,3,5).forEach { sec ->
                                    HydraChoiceButton(uiRefreshSeconds == sec, "${sec}s", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { uiRefreshSeconds = sec; appSettings.uiRefreshSeconds = sec }, modifier = Modifier.height(30.dp)); Spacer(Modifier.width(6.dp))
                                }
                            }
                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(if (language == AppLanguage.EN) "Permissive applications" else "Aplicaciones permisivas", style = MaterialTheme.typography.titleMedium)
                            Text(if (language == AppLanguage.EN) "Apps marked here are allowed when they have no explicit rule, helping prevent accidental loss of basic phone functions." else "Las apps marcadas aquí se permiten cuando no tienen una regla explícita, para evitar cortes accidentales de funciones básicas.", style = MaterialTheme.typography.bodySmall)
                            Button({ showEssentialDialog = true }) { Text(if (language == AppLanguage.EN) "Choose permissive apps" else "Elegir apps permisivas") }
                            if (essentialAppsStore.uids.isNotEmpty()) {
                                Text(if (language == AppLanguage.EN) "Selected: ${essentialAppsStore.uids.size}" else "Seleccionadas: ${essentialAppsStore.uids.size}", style = MaterialTheme.typography.labelSmall)
                            }
                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(tr(context,"security"), style = MaterialTheme.typography.titleMedium)
                            SecuritySettingsSection(context, LockStore(context), onChanged = { })

                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(tr(context,"language"), style = MaterialTheme.typography.titleMedium)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                listOf(AppLanguage.SYSTEM to tr(context,"system_language"), AppLanguage.ES to tr(context,"spanish"), AppLanguage.EN to tr(context,"english")).forEach { (mode, label) ->
                                    HydraChoiceButton(language == mode, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { language = mode; settingsStore.language = mode }, modifier = Modifier.height(30.dp))
                                    Spacer(Modifier.width(8.dp))
                                }
                            }
                            Spacer(Modifier.height(12.dp)); HorizontalDivider(); Spacer(Modifier.height(12.dp))
                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(tr(context,"appearance"), style = MaterialTheme.typography.titleMedium)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                listOf(ThemeMode.SYSTEM to tr(context,"system_language"), ThemeMode.LIGHT to if (language == AppLanguage.EN) "Light" else "Claro", ThemeMode.DARK to if (language == AppLanguage.EN) "Dark" else "Oscuro").forEach { (mode,label) ->
                                    HydraChoiceButton(themeMode == mode, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick={ themeMode=mode; settingsStore.themeMode=mode }, modifier=Modifier.height(30.dp)); Spacer(Modifier.width(8.dp))
                                }
                            }
                            Spacer(Modifier.height(14.dp)); HorizontalDivider(); Spacer(Modifier.height(14.dp))
                            Text(tr(context,"maintenance"), style = MaterialTheme.typography.titleMedium)
                            Text(if (language == AppLanguage.EN) "Automatic history cleanup" else "Limpiar historial automáticamente", style = MaterialTheme.typography.bodyMedium)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                listOf(12 to "12 h", 24 to if (language == AppLanguage.EN) "24 h" else "24 h", 24 * 7 to tr(context,"days7"), 24 * 30 to tr(context,"days30"), 0 to tr(context,"never")).forEach { (hours, label) ->
                                    HydraChoiceButton(retentionHours == hours, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { retentionHours = hours; ConnectionHistory.setRetentionHours(context, hours); history = ConnectionHistory.snapshot() }, modifier=Modifier.height(30.dp))
                                    Spacer(Modifier.width(8.dp))
                                }
                            }
                            Text(if (language == AppLanguage.EN) "Maximum history records" else "Máximo de registros del historial", style = MaterialTheme.typography.bodyMedium)
                            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp)) {
                                listOf(250,500,1000).forEach { n ->
                                    HydraChoiceButton(historyMaxRecords == n, n.toString(), Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { historyMaxRecords=n; appSettings.historyMaxRecords=n; ConnectionHistory.setMaxRecords(context,n); history=ConnectionHistory.snapshot() }, modifier=Modifier.height(30.dp))
                                    Spacer(Modifier.width(6.dp))
                                }
                            }
                            Button({ onExportHistory() }) { Text(if (language == AppLanguage.EN) "Export history CSV" else "Exportar historial CSV") }
                            Button({ ConnectionHistory.clear(); TrafficStatsStore.clear(); AppDailyUsageStore.clear(); DiagnosticLogger.clearBuffer(); TrafficAnalyzerStore.clear(); history = emptyList(); stats = emptyList() }) { Text(tr(context,"clear_all")) }
                            Spacer(Modifier.height(6.dp))
                            Button({ showResetDialog=true }) { Text(tr(context,"reset_rules")) }
                            if (showResetDialog) AlertDialog(
                                onDismissRequest={showResetDialog=false},
                                title={Text(tr(context,"reset_rules"))},
                                text={Text(tr(context,"reset_rules_body"))},
                                confirmButton={TextButton({ resetRulesToDefaults(ruleStore, advancedRuleStore, ipBlockStore); ruleVersion++; advancedVersion++; ipVersion++; profileVersion++; showResetDialog=false; notifyRulesChanged(context) }) { Text(tr(context,"reset")) }},
                                dismissButton={TextButton({showResetDialog=false}) { Text(tr(context,"cancel")) }}
                            )
                            Spacer(Modifier.height(24.dp))
                        }
                    }
                }
            }
        }
    }

    if (showAlwaysOnPrompt) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showAlwaysOnPrompt = false },
            title = { Text(if (language == AppLanguage.EN) "Keep protection on after a restart" else "Mantener la protección tras reiniciar") },
            text = { Text(if (language == AppLanguage.EN)
                "Android asks you to re-approve the VPN every time the phone restarts. If you don't, Hydra Firewall stays OFF after a reboot even though it was ON before.\n\nTo fix this, activate \"Always-on VPN\" for Hydra Firewall in Android's VPN settings. With that on, Android starts Hydra automatically after every restart, without asking again.\n\nYou can do this now or later from Settings → Always-on VPN."
                else
                "Android pide volver a aprobar la VPN cada vez que el teléfono se reinicia. Si no lo hacés, Hydra Firewall queda APAGADO después de reiniciar, aunque estuviera encendido antes.\n\nPara solucionarlo, activá \"VPN siempre activa\" para Hydra Firewall en los ajustes de VPN de Android. Con eso activado, Android inicia Hydra automáticamente después de cada reinicio, sin volver a preguntar.\n\nPodés hacerlo ahora o más tarde desde Ajustes → VPN siempre activa.") },
            confirmButton = { TextButton({ showAlwaysOnPrompt = false; startActivitySafe(context, Settings.ACTION_VPN_SETTINGS) }) { Text(if (language == AppLanguage.EN) "Open VPN settings" else "Abrir ajustes de VPN") } },
            dismissButton = { TextButton({ showAlwaysOnPrompt = false }) { Text(if (language == AppLanguage.EN) "Later" else "Más tarde") } }
        )
    }

    if (systemAppsWarning) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { systemAppsWarning = false },
            title = { Text(if (language == AppLanguage.EN) "System applications" else "Aplicaciones del sistema") },
            text = { Text(if (language == AppLanguage.EN)
                "These apps belong to Android or device software. Blocking some can break telephony, Wi‑Fi, settings, updates, notifications or Google services. HYDRA will flag known critical packages as HIGH RISK, but roles vary by Android version and manufacturer."
                else
                "Estas apps pertenecen a Android o al software del dispositivo. Bloquear algunas puede romper telefonía, Wi‑Fi, ajustes, actualizaciones, notificaciones o servicios de Google. HYDRA marcará paquetes críticos conocidos como ALTO RIESGO, pero las funciones varían según la versión de Android y el fabricante.") },
            confirmButton = { TextButton({ systemAppsWarning = false }) { Text(tr(context, "close")) } }
        )
    }

    if (showEssentialDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showEssentialDialog = false },
            title = { Text(if (language == AppLanguage.EN) "Permissive applications" else "Aplicaciones permisivas") },
            text = {
                Column(Modifier.heightIn(max=520.dp).verticalScroll(rememberScrollState())) {
                    apps.takeIf { it.isNotEmpty() }?.let {
                        it.filter { a -> !a.isSystem || systemAppSafety(a.packageName).labelEn != "LOW RISK" }.take(80).forEach { app ->
                            val checked = essentialAppsStore.isEssential(app.uid)
                            Row(Modifier.fillMaxWidth().padding(vertical=4.dp), verticalAlignment=Alignment.CenterVertically) {
                                AppIcon(app, Modifier.size(32.dp))
                                Column(Modifier.weight(1f).padding(horizontal=8.dp)) {
                                    Text(app.label, maxLines=1, overflow=androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                                    Text(app.packageName, style=MaterialTheme.typography.labelSmall, maxLines=1, overflow=androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                                }
                                Checkbox(checked=checked, onCheckedChange={ essentialAppsStore.toggle(app.uid) })
                            }
                        }
                    } ?: Text(if (language == AppLanguage.EN) "No applications loaded yet." else "Todavía no se cargaron aplicaciones.")
                }
            },
            confirmButton = { TextButton({ showEssentialDialog = false; ruleVersion++ }) { Text(tr(context,"close")) } }
        )
    }

    selectedScheduleApp?.let { app ->
        val schedule = ruleStore.getSchedule(app.uid)
        val dialogColors = hydraDialogColors()
        Dialog(onDismissRequest = { selectedScheduleApp = null }) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .widthIn(max = 520.dp),
                shape = RoundedCornerShape(18.dp),
                color = dialogColors.first,
                contentColor = dialogColors.second,
                tonalElevation = 0.dp,
                shadowElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(20.dp)
                ) {
                    Text(
                        if (language == AppLanguage.EN) "Schedule — ${app.label}" else "Horario — ${app.label}",
                        color = dialogColors.second,
                        style = MaterialTheme.typography.titleLarge
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        app.packageName,
                        color = dialogColors.third,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.height(10.dp))
                    ScheduleEditor(context, schedule) { updated ->
                        ruleStore.setSchedule(app.uid, updated)
                        ruleVersion++
                        notifyRulesChanged(context)
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(
                            onClick = { selectedScheduleApp = null },
                            colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.primary)
                        ) { Text(tr(context, "close")) }
                    }
                }
            }
        }
    }

    selectedCustomApp?.let { app ->
        CustomProtectionEditorDialog(
            context = context,
            app = app,
            store = customProtectionStore,
            ruleStore = ruleStore,
            english = language == AppLanguage.EN,
            onDismiss = { selectedCustomApp = null },
            onApply = { profile ->
                val existingRule = ruleStore.hasExplicitRule(app.uid)
                val currentRule = ruleStore.getRule(app.uid)
                // PERSONALIZADO is an explicit app mode. For a never-configured
                // app, start with both networks enabled so the selected profile
                // is immediately testable; existing network restrictions remain
                // untouched.
                if (!existingRule) {
                    ruleStore.setWifiAllowed(app.uid, true)
                    ruleStore.setMobileAllowed(app.uid, true)
                } else {
                    ruleStore.setWifiAllowed(app.uid, currentRule.wifiAllowed)
                    ruleStore.setMobileAllowed(app.uid, currentRule.mobileAllowed)
                }
                customProtectionStore.set(app.uid, profile)
                AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.CUSTOM)
                ruleVersion++
                notifyRulesChanged(context)
                selectedCustomApp = null
            }
        )
    }

    selectedApp?.let { app ->
        val policyRefresh = ruleVersion
        val compatibilityMode = AppCompatibilityPolicyStore.getMode(app.packageName)
        val customProfile = remember(policyRefresh) { customProtectionStore.get(app.uid) }
        val s = TrafficStatsStore.snapshot(app.uid)
        val rule = ruleStore.getRule(app.uid)
        val explicitRule = ruleStore.hasExplicitRule(app.uid)
        val userEssential = essentialAppsStore.isUserEssential(app.uid) || compatibilityMode == AppCompatibilityMode.ESSENTIAL || compatibilityMode == AppCompatibilityMode.ESSENTIAL_COMPAT
        val autoEssential = essentialAppsStore.isAutoEssential(app.uid)
        val trustedAutoAllowed = trustedAppsEnabled && TrustedAppsDetector.isTrusted(context, app.uid)
        val noFirewall = compatibilityMode == AppCompatibilityMode.EXCLUDED
        val effectiveWifi = if (noFirewall) false else if (!explicitRule && (autoEssential || trustedAutoAllowed)) true else rule.wifiAllowed
        val effectiveMobile = if (noFirewall) false else if (!explicitRule && (autoEssential || trustedAutoAllowed)) true else rule.mobileAllowed

        val policyColor = appRulePolicyColor(noFirewall, effectiveWifi, effectiveMobile)
        val runningProcesses = remember(app.uid) { loadRunningProcesses(context, app.uid) }
        val uidPermissionPackages = remember(app.uid) { loadUidPermissionGroups(context, app.uid) }
        val recentDecisions = remember(history, app.uid) {
            history.filter { it.uid == app.uid }.takeLast(12).asReversed()
        }
        val dialogColors = hydraDialogColors()
        Dialog(onDismissRequest = { selectedApp = null }) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .widthIn(max = 520.dp)
                    .heightIn(max = 620.dp),
                shape = RoundedCornerShape(18.dp),
                color = dialogColors.first,
                tonalElevation = 0.dp,
                shadowElevation = 8.dp
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 300.dp, max = 620.dp)
                        .padding(20.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                            .verticalScroll(rememberScrollState())
                    ) {
                    Text(app.label, color = dialogColors.second, style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        if (app.isSystem) tr(context,"system_app_label") else app.packageName,
                        color = dialogColors.third,
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text("UID ${app.uid}", color = dialogColors.third, style = MaterialTheme.typography.bodySmall)
                    Text(
                        "${if (language == AppLanguage.EN) "Process" else "Proceso"}: ${app.processName}",
                        color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                    )
                    if (runningProcesses.isNotEmpty()) {
                        Text(
                            if (language == AppLanguage.EN) "Running PID(s): ${runningProcesses.joinToString(", ") { it.pid.toString() }}"
                            else "PID en ejecución: ${runningProcesses.joinToString(", ") { it.pid.toString() }}",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    val sharedPackages = remember(app.uid) {
                        runCatching { context.packageManager.getPackagesForUid(app.uid)?.toList().orEmpty() }.getOrDefault(emptyList())
                    }
                    if (sharedPackages.size > 1) {
                        Text(
                            if (language == AppLanguage.EN)
                                "This UID is shared by ${sharedPackages.size} apps. Wi‑Fi/Mobile rules and schedules are applied to the shared UID."
                            else
                                "Este UID es compartido por ${sharedPackages.size} apps. Las reglas Wi‑Fi/Móvil y los horarios se aplican al UID compartido.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    if (compatibilityMode == AppCompatibilityMode.CUSTOM) {
                        Text(
                            if (language == AppLanguage.EN) "CUSTOM · PROTECTIONS" else "PERSONALIZADO · PROTECCIONES",
                            color = policyColor, style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            if (language == AppLanguage.EN)
                                "The app stays inside HYDRA. Only the protection switches selected below are applied; Wi‑Fi/Mobile permissions remain separate."
                            else
                                "La app permanece dentro de HYDRA. Solo se aplican las protecciones seleccionadas abajo; los permisos Wi‑Fi/Móvil siguen siendo independientes.",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            customProtectionSummary(customProfile, language == AppLanguage.EN),
                            color = policyColor, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (compatibilityMode == AppCompatibilityMode.ESSENTIAL_COMPAT) {
                        Text(
                            if (language == AppLanguage.EN) "PERMISSIVE-COMPAT · DIAGNOSTIC MODE" else "PERMISIVO-COMPAT · MODO DIAGNÓSTICO",
                            color = policyColor, style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            if (language == AppLanguage.EN) "Diagnostic only: the app stays inside HYDRA, but the normal ad/tracker domain blocklist and QUIC domain filter are bypassed. Explicit user domain BLOCK rules and confirmed threat protections remain active."
                            else "Solo diagnóstico: la app sigue dentro de HYDRA, pero se saltean el bloqueo normal de dominios de ads/trackers y el filtro de dominios QUIC. Las reglas de dominio BLOQUEAR del usuario y las amenazas confirmadas siguen activas.",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (userEssential && compatibilityMode != AppCompatibilityMode.ESSENTIAL_COMPAT) {
                        Text(
                            if (language == AppLanguage.EN) "PERMISSIVE · FLEXIBLE FILTERS" else "PERMISIVO · FILTROS FLEXIBLES",
                            color = policyColor, style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            if (language == AppLanguage.EN) "The app stays inside HYDRA with more flexible compatibility rules. The selected Wi‑Fi/Mobile permissions remain active; strong threat/IP protections still apply."
                            else "La app sigue dentro de HYDRA con reglas de compatibilidad más flexibles. Se respetan los permisos Wi‑Fi/Móvil elegidos; siguen aplicándose las protecciones fuertes de amenazas/IP.",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (autoEssential && !explicitRule && !userEssential) {
                        Text(
                            if (language == AppLanguage.EN) "SYSTEM ESSENTIAL · ALLOWED AUTOMATICALLY" else "ESENCIAL DEL SISTEMA · PERMITIDA AUTOMÁTICAMENTE",
                            color = policyColor, style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            if (language == AppLanguage.EN) "Only the normal app default is bypassed. Threat/IP/global lockdown rules still apply." else "Solo se evita el bloqueo predeterminado de la app. Siguen aplicándose amenazas, IP y bloqueo global.",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (noFirewall) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            if (language == AppLanguage.EN) "NO FIREWALL · APP OUTSIDE HYDRA" else "SIN FIREWALL · APP FUERA DE HYDRA",
                            color = policyColor, style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            if (language == AppLanguage.EN) "For banking or special applications that do not allow use of a filtered network. Wi‑Fi/Mobile firewall switches do not apply while the app is outside the VPN."
                            else "Para aplicaciones bancarias o especiales que no permiten usar una red filtrada. Los controles Wi‑Fi/Móvil del firewall no se aplican mientras la app está fuera de la VPN.",
                            color = dialogColors.third, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    val ruleDetail = when {
                        noFirewall -> if (language == AppLanguage.EN)
                            "FULL CONNECTIVITY · no HYDRA filtering. The app is outside the VPN; HYDRA Wi‑Fi/Mobile switches do not apply."
                        else
                            "CONECTIVIDAD COMPLETA · sin filtrado de HYDRA. La app queda fuera de la VPN; los controles Wi‑Fi/Móvil de HYDRA no se aplican."
                        compatibilityMode == AppCompatibilityMode.ESSENTIAL_COMPAT -> if (language == AppLanguage.EN)
                            "PERMISSIVE-COMPAT · stays inside HYDRA. Optional domain/QUIC filtering is temporarily bypassed for diagnosis; Wi‑Fi/Mobile still follow the app rule and strong threat/IP protection remains active."
                        else
                            "PERMISIVO-COMPAT · permanece dentro de HYDRA. Se saltea temporalmente el filtrado opcional de dominios/QUIC para diagnóstico; Wi‑Fi/Móvil siguen la regla de la app y las protecciones fuertes contra amenazas/IP siguen activas."
                        userEssential -> if (language == AppLanguage.EN)
                            "PERMISSIVE · remains inside HYDRA. Wi‑Fi/Mobile follow the switches below; compatibility layers are relaxed while strong threat/IP protection remains active."
                        else
                            "PERMISIVO · permanece dentro de HYDRA. Wi‑Fi/Móvil siguen los interruptores de abajo; se relajan capas de compatibilidad y se mantienen las protecciones fuertes contra amenazas/IP."
                        explicitRule -> when {
                            effectiveWifi && effectiveMobile -> if (language == AppLanguage.EN)
                                "FULL CONNECTIVITY · Wi‑Fi and mobile are allowed through HYDRA; normal ads/trackers and security controls remain active."
                            else
                                "CONECTIVIDAD COMPLETA · Wi‑Fi y datos móviles permitidos a través de HYDRA; siguen activos los bloqueos normales de ads/trackers y seguridad."
                            effectiveWifi -> if (language == AppLanguage.EN)
                                "WI‑FI ONLY · mobile data is blocked for this app; HYDRA filtering and security controls remain active."
                            else
                                "SOLO WI‑FI · los datos móviles quedan bloqueados para esta app; el filtrado y la seguridad de HYDRA siguen activos."
                            effectiveMobile -> if (language == AppLanguage.EN)
                                "MOBILE ONLY · Wi‑Fi is blocked for this app; HYDRA filtering and security controls remain active."
                            else
                                "SOLO DATOS MÓVILES · el Wi‑Fi queda bloqueado para esta app; el filtrado y la seguridad de HYDRA siguen activos."
                            else -> if (language == AppLanguage.EN)
                                "BLOCKED · Wi‑Fi and mobile data are blocked for this app."
                            else
                                "BLOQUEADA · Wi‑Fi y datos móviles quedan bloqueados para esta app."
                        }
                        trustedAutoAllowed -> if (language == AppLanguage.EN)
                            "TRUSTED APP · automatically allowed because the Apps de confianza switch is enabled; security controls still remain authoritative."
                        else
                            "APP DE CONFIANZA · permitida automáticamente porque está activado Apps de confianza; las protecciones de seguridad siguen siendo autoritarias."
                        autoEssential -> if (language == AppLanguage.EN)
                            "SYSTEM ESSENTIAL · allowed by the conservative core-system policy; ordinary apps are not auto-allowed."
                        else
                            "ESENCIAL DEL SISTEMA · permitido solo para identidades centrales de Android; las apps normales no se autorizan automáticamente."
                        else -> if (language == AppLanguage.EN)
                            "DEFAULT BLOCK · the app has no explicit network rule and remains blocked until a rule is chosen."
                        else
                            "BLOQUEO POR DEFECTO · la app no tiene una regla de red explícita y permanece bloqueada hasta elegir una."
                    }
                    Text(
                        ruleDetail,
                        color = policyColor,
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (app.isSystem) {
                        val safety = systemAppSafety(app.packageName)
                        Spacer(Modifier.height(6.dp))
                        Text(
                            if (language == AppLanguage.EN) "Safety: ${safety.labelEn}" else "Seguridad: ${safety.labelEs}",
                            color = safety.color,
                            style = MaterialTheme.typography.labelMedium
                        )
                        Text(if (language == AppLanguage.EN) safety.detailEn else safety.detailEs, color = dialogColors.third, style = MaterialTheme.typography.bodySmall)
                    }
                    Spacer(Modifier.height(10.dp))
                    if (noFirewall) {
                        Text(
                            if (language == AppLanguage.EN) "Wi‑Fi/Mobile firewall switches: NOT APPLICABLE (app is outside HYDRA)"
                            else "Controles Wi‑Fi/Móvil del firewall: NO APLICAN (la app está fuera de HYDRA)",
                            color = dialogColors.third
                        )
                    } else {
                        Text("Wi‑Fi: ${if (effectiveWifi) tr(context,"allow") else tr(context,"block")}", color = dialogColors.third)
                        Text("Móvil: ${if (effectiveMobile) tr(context,"allow") else tr(context,"block")}", color = dialogColors.third)
                    }
                    Text(
                        if (explicitRule) (if (language == AppLanguage.EN) "Policy: EXPLICIT RULE" else "Política: REGLA EXPLÍCITA")
                        else if (trustedAutoAllowed) (if (language == AppLanguage.EN) "Policy: TRUSTED APP AUTO-ALLOW" else "Política: APP DE CONFIANZA AUTO-PERMITIDA")
                        else if (autoEssential) (if (language == AppLanguage.EN) "Policy: SYSTEM CORE" else "Política: SISTEMA CENTRAL")
                        else (if (language == AppLanguage.EN) "Policy: DEFAULT BLOCK / PROMPT" else "Política: BLOQUEO / PREGUNTA")
                        ,
                        color = policyColor,
                        style = MaterialTheme.typography.labelSmall
                    )
                    Spacer(Modifier.height(8.dp))
                    Text("${tr(context,"connections_word")}: ${s.connections}", color = dialogColors.third)
                    Text("${tr(context,"blocked_word")}: ${s.blocked}", color = dialogColors.third)
                    Text("↑ ${formatBytes(s.txBytes)}  ↓ ${formatBytes(s.rxBytes)}", color = dialogColors.third)
                    if (runningProcesses.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(if (language == AppLanguage.EN) "Processes (best effort; not thread IDs)" else "Procesos (mejor esfuerzo; no son IDs de hilo)", style = MaterialTheme.typography.titleSmall)
                        runningProcesses.forEach { proc ->
                            Text("• ${proc.processName} · PID ${proc.pid}", color = dialogColors.third, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    if (uidPermissionPackages.any { it.groups.isNotEmpty() }) {
                        Spacer(Modifier.height(8.dp))
                        Text(if (language == AppLanguage.EN) "Permissions grouped by app / UID" else "Permisos agrupados por app / UID", style = MaterialTheme.typography.titleSmall)
                        uidPermissionPackages.filter { it.groups.isNotEmpty() }.take(6).forEach { pkg ->
                            Text("${pkg.label} · ${pkg.packageName}", style = MaterialTheme.typography.labelMedium)
                            pkg.groups.take(6).forEach { group ->
                                Text("${group.label} (${group.permissions.size})", style = MaterialTheme.typography.labelSmall)
                                group.permissions.take(6).forEach { perm ->
                                    Text("• ${perm.substringAfterLast('.')}", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                    if (recentDecisions.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(if (language == AppLanguage.EN) "Recent firewall decisions" else "Últimas decisiones del firewall", style = MaterialTheme.typography.titleSmall)
                        recentDecisions.forEach { record ->
                            val status = if (record.allowed) "ALLOW" else "BLOCK"
                            Text(
                                "$status · ${record.protocol} · ${record.destination} · ${record.event}",
                                color = if (record.allowed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 2,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                            )
                        }
                    }
                        Spacer(Modifier.height(14.dp))
                    }
                    HorizontalDivider()
                    Spacer(Modifier.height(6.dp))
                    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(
                            onClick = {
                                ruleStore.clearRule(app.uid)
                                ruleStore.clearTemporaryRule(app.uid)
                                customProtectionStore.clear(app.uid)
                                AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.NORMAL)
                                ruleVersion++
                                notifyRulesChanged(context)
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                if (language == AppLanguage.EN)
                                    "Reset rule (ask again)"
                                else
                                    "Restablecer regla (preguntar de nuevo)",
                                maxLines = 2, textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                        }
                    Column(
                        Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        if (!noFirewall) {
                            OutlinedButton(
                                onClick = { selectedCustomApp = app },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (language == AppLanguage.EN) "Custom" else "Personalizado", maxLines = 1)
                            }
                        }
                        if (userEssential) {
                            TextButton(
                                onClick = {
                                    AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.NORMAL)
                                    ruleVersion++
                                    notifyRulesChanged(context)
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (language == AppLanguage.EN) "Remove permissive mode" else "Quitar modo permisivo")
                            }
                        } else {
                            Button(
                                onClick = {
                                    // ESENCIAL is an explicit connectivity mode. Do not
                                    // inherit a stale BLOCK/BLOCK rule from a previous
                                    // prompt/quarantine/test; start with both transports
                                    // enabled and let the user disable one afterward.
                                    ruleStore.setWifiAllowed(app.uid, true)
                                    ruleStore.setMobileAllowed(app.uid, true)
                                    AppCompatibilityController.setModeAndRestart(context, app.packageName, AppCompatibilityMode.ESSENTIAL)
                                    ruleVersion++
                                    notifyRulesChanged(context)
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (language == AppLanguage.EN) "Permissive mode" else "Modo permisivo")
                            }
                        }
                    }
                    }
                    if (userEssential && !noFirewall) {
                        Spacer(Modifier.height(6.dp))
                        OutlinedButton(
                            onClick = {
                                val target = if (compatibilityMode == AppCompatibilityMode.ESSENTIAL_COMPAT)
                                    AppCompatibilityMode.ESSENTIAL
                                else
                                    AppCompatibilityMode.ESSENTIAL_COMPAT
                                // The compatibility test must actually be testable from
                                // a default BLOCK/BLOCK app. Grant both networks only when
                                // no explicit rule exists; never override an explicit user
                                // block.
                                ruleStore.setWifiAllowed(app.uid, true)
                                ruleStore.setMobileAllowed(app.uid, true)
                                AppCompatibilityController.setModeAndRestart(context, app.packageName, target)
                                ruleVersion++
                                notifyRulesChanged(context)
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                if (compatibilityMode == AppCompatibilityMode.ESSENTIAL_COMPAT)
                                    if (language == AppLanguage.EN) "Back to PERMISSIVE" else "Volver a PERMISIVO"
                                else
                                    if (language == AppLanguage.EN) "Test PERMISSIVE-COMPAT" else "Probar PERMISIVO-COMPAT"
                            )
                        }
                    }
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        Button(
                            onClick = { selectedApp = null },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF173A5E),
                                contentColor = Color.White
                            )
                        ) {
                            Text(tr(context, "close"))
                        }
                    }
                }
            }
        }
    }


}

enum class HistorySort { TIME, APP, IP, PORT }

private fun historySortLabel(context: Context, sort: HistorySort): String = when (sort) {
    HistorySort.TIME -> tr(context, "sort_time")
    HistorySort.APP -> tr(context, "sort_app")
    HistorySort.IP -> tr(context, "sort_ip")
    HistorySort.PORT -> tr(context, "sort_port")
}

private fun extractHost(address: String): String {
    val value = address.trim()
    if (value.startsWith("[")) {
        val end = value.indexOf(']')
        if (end > 1) return value.substring(1, end)
    }
    val colon = value.lastIndexOf(':')
    return if (colon > 0 && value.substring(colon + 1).toIntOrNull() != null) value.substring(0, colon) else value
}

private fun extractPort(address: String): Int {
    val value = address.trim()
    val port = value.substringAfterLast(':', "")
    return port.toIntOrNull() ?: -1
}

private fun serviceLabelForPort(port: Int): String = when (port) {
    53 -> "DNS"
    80 -> "HTTP"
    443 -> "HTTPS"
    853 -> "DoT"
    1900 -> "SSDP"
    3478, 3479 -> "STUN"
    5228, 5229, 5230 -> "Google"
    123 -> "NTP"
    else -> "TCP/UDP"
}

private fun serviceLabel(destination: String): String = serviceLabelForPort(extractPort(destination))

@Composable
private fun LiveTrafficChart(history: List<Pair<Float, Float>>) {
    val allowedColor = Color(0xFF2E7D32)
    val blockedColor = Color(0xFFC62828)
    val language = AppSettings(LocalContext.current).language
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).background(allowedColor, shape = androidx.compose.foundation.shape.CircleShape))
            Spacer(Modifier.width(4.dp)); Text(if (language == AppLanguage.EN) "Allowed" else "Permitido", style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.width(10.dp))
            Box(Modifier.size(8.dp).background(blockedColor, shape = androidx.compose.foundation.shape.CircleShape))
            Spacer(Modifier.width(4.dp)); Text(if (language == AppLanguage.EN) "Blocked" else "Bloqueado", style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.width(10.dp))
            Text(if (language == AppLanguage.EN) "MB per interval" else "MB por intervalo", style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(4.dp))
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(128.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(6.dp)
        ) {
            val allowedMax = history.maxOfOrNull { it.first }?.coerceAtLeast(0.01f) ?: 0.01f
            val blockedMax = history.maxOfOrNull { it.second }?.coerceAtLeast(0.01f) ?: 0.01f
            val maxVal = maxOf(allowedMax, blockedMax)
            if (history.size >= 2) {
                val stepX = size.width / (history.size - 1).coerceAtLeast(1)
                fun pointY(v: Float): Float = size.height - (v / maxVal) * size.height
                fun pathFor(pick: (Pair<Float, Float>) -> Float) = androidx.compose.ui.graphics.Path().apply {
                    history.forEachIndexed { i, v ->
                        val x = i * stepX
                        val y = pointY(pick(v))
                        if (i == 0) moveTo(x, y) else lineTo(x, y)
                    }
                }
                drawPath(pathFor { it.first }, color = allowedColor, style = Stroke(width = 2.2f))
                drawPath(pathFor { it.second }, color = blockedColor, style = Stroke(width = 2.2f))

                val paint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
                    textSize = 18f
                    typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
                }
                fun drawPeakLabel(index: Int, value: Float, color: Color, upward: Boolean) {
                    if (value <= 0f) return
                    val x = (index * stepX).coerceIn(4f, size.width - 44f)
                    val y = (pointY(value) + if (upward) -4f else 18f).coerceIn(12f, size.height - 2f)
                    paint.color = android.graphics.Color.WHITE
                    val label = formatTrafficMb(value)
                    drawContext.canvas.nativeCanvas.drawText(label, x, y, paint)
                }
                for (i in 1 until history.lastIndex) {
                    val a = history[i].first
                    if (a > 0f && a >= history[i-1].first && a >= history[i+1].first) drawPeakLabel(i, a, allowedColor, true)
                    val b = history[i].second
                    if (b > 0f && b >= history[i-1].second && b >= history[i+1].second) drawPeakLabel(i, b, blockedColor, false)
                }
            }
        }
    }
}

@Composable
private fun TrafficTotalsBarChart(allowedBytes: Long, blockedBytes: Long) {
    val context = LocalContext.current
    val allowedColor = Color(0xFF2E7D32)
    val blockedColor = Color(0xFFC62828)
    val max = maxOf(allowedBytes, blockedBytes, 1L).toDouble()
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(if (AppSettings(context).language == AppLanguage.EN) "Traffic volume" else "Volumen de tráfico", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(6.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(8.dp).height(24.dp).background(allowedColor, androidx.compose.foundation.shape.RoundedCornerShape(4.dp)))
            Spacer(Modifier.width(6.dp))
            Text(if (AppSettings(context).language == AppLanguage.EN) "Allowed" else "Permitido", Modifier.width(72.dp), style = MaterialTheme.typography.bodySmall)
            Box(Modifier.weight(1f).height(24.dp).clip(androidx.compose.foundation.shape.RoundedCornerShape(5.dp)).background(MaterialTheme.colorScheme.surfaceVariant)) {
                Box(Modifier.fillMaxHeight().fillMaxWidth((allowedBytes.toDouble() / max).toFloat()).background(allowedColor))
            }
            Spacer(Modifier.width(8.dp))
            Text(formatBytes(allowedBytes), style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.height(6.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(8.dp).height(24.dp).background(blockedColor, androidx.compose.foundation.shape.RoundedCornerShape(4.dp)))
            Spacer(Modifier.width(6.dp))
            Text(if (AppSettings(context).language == AppLanguage.EN) "Blocked" else "Bloqueado", Modifier.width(72.dp), style = MaterialTheme.typography.bodySmall)
            Box(Modifier.weight(1f).height(24.dp).clip(androidx.compose.foundation.shape.RoundedCornerShape(5.dp)).background(MaterialTheme.colorScheme.surfaceVariant)) {
                Box(Modifier.fillMaxHeight().fillMaxWidth((blockedBytes.toDouble() / max).toFloat()).background(blockedColor))
            }
            Spacer(Modifier.width(8.dp))
            Text(formatBytes(blockedBytes), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun TrafficUsageChart(stats: List<TrafficStatsStore.Snapshot>) {
    val top = stats.map { it to (it.txBytes + it.rxBytes) }.sortedByDescending { it.second }.take(6)
    val max = top.maxOfOrNull { it.second }?.coerceAtLeast(1L) ?: 1L
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        if (top.isEmpty()) {
            Text(tr(LocalContext.current,"no_data"), style = MaterialTheme.typography.bodySmall)
        } else {
            top.forEach { (s, total) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text((s.packageName ?: "UID ${s.uid}").take(18), Modifier.width(140.dp), style = MaterialTheme.typography.bodySmall)
                    LinearProgressIndicator(progress = { (total.toDouble() / max.toDouble()).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.weight(1f))
                    Text(formatBytes(total), Modifier.padding(start = 8.dp), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun IpRulesPanel(context: Context, english: Boolean, store: IpBlockStore, version: Int, onChanged: () -> Unit) {
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
                    Card(Modifier.fillMaxWidth().padding(vertical = 3.dp).clickable { selected = rule }) {
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
private fun PortRulesPanel(
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
            HydraChoiceButton(scopeGlobal, "GLOBAL", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { scopeGlobal = true; selectedUid = null }, modifier = Modifier.height(30.dp))
            HydraChoiceButton(!scopeGlobal, if (english) "APPLICATION" else "APLICACIÓN", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { scopeGlobal = false }, modifier = Modifier.height(30.dp))
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
            HydraChoiceButton(protocol == "TCP", "TCP", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { protocol = "TCP" }, modifier=Modifier.height(30.dp))
            Spacer(Modifier.width(4.dp))
            HydraChoiceButton(protocol == "UDP", "UDP", Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { protocol = "UDP" }, modifier=Modifier.height(30.dp))
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
                        app?.label ?: "UID ${rule.uid}"
                    }
                    Card(
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
            app?.label ?: "UID ${rule.uid}"
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
private fun CustomProtectionEditorDialog(
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
private fun CustomProtectionChecklist(
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

private fun customProtectionSummary(profile: CustomProtectionProfileStore.Profile, english: Boolean): String {
    val enabled = mutableListOf<String>()
    if (profile.adTrackerBlocklist) enabled += if (english) "ads/trackers" else "ads/trackers"
    if (profile.secureDns) enabled += "DNS"
    if (profile.tlsSniFilter) enabled += "SNI"
    if (profile.quicProtection) enabled += "QUIC"
    if (profile.tlsFingerprint) enabled += "TLS FP"
    if (profile.threatProtection) enabled += if (english) "threats" else "amenazas"
    if (profile.blockLocalNetwork) enabled += if (english) "local network block" else "bloqueo red local"
    return if (english) {
        "Active: ${if (enabled.isEmpty()) "none" else enabled.joinToString(", ") }"
    } else {
        "Activas: ${if (enabled.isEmpty()) "ninguna" else enabled.joinToString(", ") }"
    }
}

@Composable
private fun AdvancedRulesEditor(context: Context, apps: List<AppEntry>, store: AdvancedRuleStore, version: Int, onChanged: () -> Unit, english: Boolean) {
    var selectedUid by remember { mutableStateOf<Int?>(null) }
    var protocol by remember { mutableStateOf("TCP") }
    var portText by remember { mutableStateOf("443") }
    var allow by remember { mutableStateOf(false) }
    var selectedRule by remember { mutableStateOf<AdvancedRuleStore.Rule?>(null) }
    val rules = remember(version) { store.getAll() }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        var expanded by remember { mutableStateOf(false) }
        Box { TextButton({ expanded = true }) { Text(apps.firstOrNull { it.uid == selectedUid }?.label ?: if(english) "Choose app" else "Elegir app") }; DropdownMenu(expanded, { expanded=false }) { apps.take(80).forEach { a -> DropdownMenuItem(text={Text(a.label)}, onClick={selectedUid=a.uid; expanded=false}) } } }
        Spacer(Modifier.width(4.dp)); HydraChoiceButton(protocol == "TCP", "TCP", Color(0xFFE3D0FF), Color(0xFF241A34), onClick={ protocol="TCP" }, modifier=Modifier.height(30.dp)); Spacer(Modifier.width(4.dp)); HydraChoiceButton(protocol == "UDP", "UDP", Color(0xFFE3D0FF), Color(0xFF241A34), onClick={ protocol="UDP" }, modifier=Modifier.height(30.dp))
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
                val appLabel = apps.firstOrNull { it.uid == r.uid }?.label ?: "UID ${r.uid}"
                Card(Modifier.fillMaxWidth().padding(vertical = 3.dp).clickable { selectedRule = r }) {
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
        val appLabel = apps.firstOrNull { it.uid == rule.uid }?.label ?: "UID ${rule.uid}"
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

data class HistoryGroup(val last: ConnectionHistory.Record, val count: Int, val allowed: Int, val blocked: Int)

private fun startActivitySafe(context: Context, action: String) { runCatching { context.startActivity(Intent(action)) } }


@Composable
private fun ProtectionTabContent(
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
    onToggleVpn: (Boolean) -> Unit,
    onGlobalBlockAllChange: (Boolean) -> Unit,
    onThreatProtectionChange: (Boolean) -> Unit,
    onCheckBlocklist: () -> Unit,
    onUpdateBlocklist: () -> Unit,
    onKillSwitch: () -> Unit
) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 10.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text(
            if (language == AppLanguage.EN) "Core protection controls" else "Controles básicos de protección",
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            if (language == AppLanguage.EN)
                "The essential protection switches are managed here. Advanced configuration remains in Settings."
            else
                "Los interruptores esenciales de protección se administran aquí. La configuración avanzada queda en Ajustes.",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(6.dp))

        Card(Modifier.fillMaxWidth()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f).padding(end = 8.dp)) {
                    Text(
                        if (language == AppLanguage.EN) "Mode: ${if (advancedMode) "ADVANCED" else "NORMAL"}" else "Modo: ${if (advancedMode) "AVANZADO" else "NORMAL"}",
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        if (language == AppLanguage.EN) "Advanced shows extra tabs (IP/Ports, Analyzer, Profiles, Test)." else "Avanzado muestra pestañas extra (IP/Puertos, Analizador, Perfiles, Prueba).",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                Switch(checked = advancedMode, onCheckedChange = onAdvancedModeChange)
            }
        }
        Spacer(Modifier.height(6.dp))

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(10.dp)) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f).padding(end = 8.dp)) {
                        Text(
                            if (language == AppLanguage.EN) "Firewall VPN" else "VPN del firewall",
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            if (language == AppLanguage.EN)
                                "Routes device traffic through Hydra for filtering."
                            else
                                "Envía el tráfico del equipo a través de Hydra para filtrarlo.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Switch(checked = isOn, onCheckedChange = onToggleVpn)
                }
                Spacer(Modifier.height(5.dp))
                Text(
                    if (isOn) {
                        if (language == AppLanguage.EN)
                            "Running • ${network.displayName}${if (roaming) " • Roaming" else ""}"
                        else
                            "Activa • ${network.displayName}${if (roaming) " • Roaming" else ""}"
                    } else {
                        if (language == AppLanguage.EN) "Stopped" else "Detenida"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isOn) Color(0xFF2E8B57) else MaterialTheme.colorScheme.error
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        SettingSwitchRow(
            if (language == AppLanguage.EN) "Block all traffic" else "Bloquear todo el tráfico",
            if (language == AppLanguage.EN)
                "Stops normal traffic decisions globally while enabled."
            else
                "Detiene globalmente las decisiones normales de tráfico mientras está activo.",
            globalBlockAll,
            onGlobalBlockAllChange
        )

        Spacer(Modifier.height(4.dp))
        SettingSwitchRow(
            if (language == AppLanguage.EN) "Threats + ads" else "Amenazas + publicidad",
            if (language == AppLanguage.EN)
                "Uses the local blocklist to block ads and trackers. Secure DNS is configured separately in Settings."
            else
                "Usa la lista local para bloquear anuncios y rastreadores. El DNS seguro se configura por separado en Ajustes.",
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

        Spacer(Modifier.height(10.dp)); HorizontalDivider(); Spacer(Modifier.height(10.dp))
        Text(if (language == AppLanguage.EN) "System kill switch" else "Kill switch del sistema", style = MaterialTheme.typography.titleMedium)
        Text(
            if (language == AppLanguage.EN)
                "This is controlled by Android VPN settings. Hydra cannot manufacture a stronger system lockdown when Android or the device firmware does not expose it."
            else
                "Esto lo controla la configuración VPN de Android. Hydra no puede crear un bloqueo del sistema más fuerte cuando Android o el firmware del equipo no lo ofrecen.",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(5.dp))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Text(
                if (FirewallVpnService.alwaysOnEnabled)
                    (if (language == AppLanguage.EN) "Always-on VPN: ✓ enabled" else "VPN siempre activa: ✓ activada")
                else
                    (if (language == AppLanguage.EN) "Always-on VPN: ✗ not enabled" else "VPN siempre activa: ✗ no activada"),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                if (FirewallVpnService.lockdownEnabled)
                    (if (language == AppLanguage.EN) "Block connections without VPN: ✓ enabled" else "Bloquear conexiones sin VPN: ✓ activado")
                else
                    (if (language == AppLanguage.EN) "Block connections without VPN: ✗ not enabled (check Android VPN settings)" else "Bloquear conexiones sin VPN: ✗ no activado (revisá Ajustes VPN de Android)"),
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            Text(
                if (language == AppLanguage.EN)
                    "Always-on VPN: Android setting available; lockdown is not exposed to a normal VPN app on this Android generation."
                else
                    "VPN siempre activa: Android ofrece el ajuste; el bloqueo sin VPN (Lockdown) no está expuesto a una app VPN normal en esta generación de Android.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (language == AppLanguage.EN)
                    "Hydra will not claim a system kill switch that the OS cannot provide."
                else
                    "Hydra no va a marcar como activo un kill switch del sistema que el sistema operativo no puede proporcionar.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(4.dp))
        Button(onClick = onKillSwitch) {
            Text(if (language == AppLanguage.EN) "OPEN VPN SETTINGS" else "ABRIR AJUSTES VPN")
        }

        Spacer(Modifier.height(10.dp)); HorizontalDivider(); Spacer(Modifier.height(10.dp))
        Text(if (language == AppLanguage.EN) "Current protection status" else "Estado actual de protección", style = MaterialTheme.typography.titleMedium)
        Text(
            when (protection.level) {
                ProtectionStatus.Level.ACTIVE -> if (language == AppLanguage.EN) "● PROTECTION ACTIVE" else "● PROTECCIÓN ACTIVA"
                ProtectionStatus.Level.PARTIAL -> if (language == AppLanguage.EN) "● PROTECTION PARTIAL" else "● PROTECCIÓN PARCIAL"
                ProtectionStatus.Level.OFF -> if (language == AppLanguage.EN) "○ PROTECTION OFF" else "○ PROTECCIÓN DESACTIVADA"
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
            if (language == AppLanguage.EN)
                "VPN: ${if (protection.vpn) "✓ active" else "✗ stopped"}"
            else
                "VPN: ${if (protection.vpn) "✓ activa" else "✗ detenida"}",
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            if (language == AppLanguage.EN) {
                "Secure DNS: ${when { !protection.secureDnsEnabled -> "off (optional)"; protection.dns -> "✓ ready"; else -> "✗ requires VPN" }}"
            } else {
                "DNS seguro: ${when { !protection.secureDnsEnabled -> "desactivado (opcional)"; protection.dns -> "✓ listo"; else -> "✗ requiere VPN" }}"
            },
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            if (language == AppLanguage.EN) {
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
            if (language == AppLanguage.EN) {
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
                if (language == AppLanguage.EN)
                    "Still missing: ${protection.missing.joinToString(" • ") }"
                else
                    "Todavía falta: ${protection.missing.joinToString(" • ") }",
                style = MaterialTheme.typography.bodySmall,
                color = if (protection.level == ProtectionStatus.Level.OFF) MaterialTheme.colorScheme.error else Color(0xFFD98E1F)
            )
        } else {
            Text(
                if (language == AppLanguage.EN) "All essential prerequisites are satisfied." else "Todos los requisitos esenciales están satisfechos.",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF2E8B57)
            )
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun SettingSwitchRow(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean)->Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical=6.dp), horizontalArrangement=Arrangement.SpaceBetween, verticalAlignment=Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end=8.dp)) { Text(title); Text(subtitle, style=MaterialTheme.typography.bodySmall) }
        Switch(checked, onCheckedChange)
    }
}

@Composable
private fun AllowBlockRow(
    label: String,
    allowed: Boolean,
    info: String,
    promptInfo: String,
    onChanged: (Boolean)->Unit
) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
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
                    label = if (allowed) "✓ Permitir por defecto" else "Permitir por defecto",
                    selectedColor = Color(0xFF00796B),
                    selectedLabelColor = Color.White,
                    onClick = { onChanged(true) },
                    fontSize = 11.sp
                )
                HydraChoiceButton(
                    selected = !allowed,
                    label = if (!allowed) "✓ Bloquear por defecto" else "Bloquear por defecto",
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


private data class SystemAppSafety(
    val labelEs: String,
    val labelEn: String,
    val detailEs: String,
    val detailEn: String,
    val color: Color
)

private fun systemAppSafety(packageName: String): SystemAppSafety {
    val p = packageName.lowercase()
    val critical = setOf(
        "com.android.systemui", "com.android.settings", "com.android.phone",
        "com.android.providers.telephony", "com.android.providers.settings",
        "com.android.packageinstaller", "com.android.permissioncontroller",
        "com.google.android.gms", "com.google.android.gsf"
    )
    if (p in critical) return SystemAppSafety(
        "ALTO RIESGO — no se recomienda bloquear", "HIGH RISK — blocking is not recommended",
        "Componente central de Android o servicio ampliamente usado. Bloquear Internet puede romper funciones básicas.",
        "Core Android or widely used Google component. Blocking Internet may break basic functions.",
        Color(0xFFC62828)
    )
    val caution = p.startsWith("com.android.providers.") || p.startsWith("com.android.server.") || p.contains("telephony") || p.contains("connectivity") || p.contains("networkstack")
    if (caution) return SystemAppSafety(
        "PRECAUCIÓN — revisar antes de bloquear", "CAUTION — review before blocking",
        "Parece un proveedor o componente de conectividad del sistema. Su función exacta depende de la versión y del fabricante.",
        "Looks like a system provider or connectivity component. Its exact role depends on Android version and manufacturer.",
        Color(0xFFF57C00)
    )
    return SystemAppSafety(
        "RIESGO NO DETERMINADO — revisar", "UNDETERMINED RISK — review",
        "No se identificó como componente crítico conocido. Esto no garantiza que sea seguro bloquearlo.",
        "Not identified as a known critical component. This does not guarantee that blocking is safe.",
        Color(0xFFF57C00)
    )
}

@Composable
private fun AppIcon(app: AppEntry?, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    AndroidView(
        modifier = modifier,
        factory = { ImageView(it).apply { scaleType = ImageView.ScaleType.CENTER_INSIDE } },
        update = { view ->
            view.setImageDrawable(app?.let { runCatching { context.packageManager.getApplicationIcon(it.packageName) }.getOrNull() })
        }
    )
}

@Composable
private fun HydraHorizontalRow(
    modifier: Modifier = Modifier,
    horizontalArrangement: Arrangement.Horizontal = Arrangement.Start,
    content: @Composable RowScope.() -> Unit
) {
    val scrollState = rememberScrollState()
    val darkMode = MaterialTheme.colorScheme.background.luminance() < 0.5f
    Box(modifier = modifier) {
        Row(
            Modifier.fillMaxWidth().horizontalScroll(scrollState),
            horizontalArrangement = horizontalArrangement,
            verticalAlignment = Alignment.CenterVertically,
            content = content
        )
        if (scrollState.maxValue > 0 && scrollState.value > 0) {
            Text("◀", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                modifier = Modifier.align(Alignment.CenterStart).padding(start = 2.dp))
        }
        if (scrollState.maxValue > 0 && scrollState.value < scrollState.maxValue) {
            Text("▶", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                modifier = Modifier.align(Alignment.CenterEnd).padding(end = 2.dp))
        }
    }
}

@Composable
private fun DnsProviderSection(
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
private fun DnsProviderOptionRow(
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
private fun BlockAdsSection(
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

@Composable
private fun DomainRulesPanel(
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
private fun HydraChoiceButton(
    selected: Boolean,
    label: String,
    selectedColor: Color,
    selectedLabelColor: Color = Color.Unspecified,
    unselectedLabelColor: Color = MaterialTheme.colorScheme.onSurface,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    fontSize: TextUnit = 11.sp
) {
    // Detect Hydra's actual rendered theme. The app supports a manual dark/light
    // setting, so Android system theme is not sufficient here.
    val darkMode = MaterialTheme.colorScheme.background.luminance() < 0.5f
    val background = if (selected) selectedColor else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    val textColor = if (selected) {
        val blockedLabel = label.equals("Bloqueadas", true) || label.equals("Blocked", true)
        when {
            blockedLabel -> if (darkMode) Color.White else Color.Black
            selectedLabelColor != Color.Unspecified -> selectedLabelColor
            selectedColor.luminance() < 0.50f -> Color.White
            else -> Color(0xFF201A23)
        }
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    Box(
        modifier = modifier
            .height(26.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(background)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            color = textColor,
            fontSize = fontSize,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
    }
}


private fun describeAppPolicy(mode: AppCompatibilityMode, wifi: Boolean, mobile: Boolean, explicit: Boolean, trusted: Boolean, english: Boolean): String {
    return when (mode) {
        AppCompatibilityMode.CUSTOM -> if (english)
            "PERSONALIZADO: the app stays inside HYDRA and uses only the protection switches selected for this app; Wi‑Fi/Mobile permissions remain separate."
        else
            "PERSONALIZADO: la app permanece dentro de HYDRA y usa solo las protecciones seleccionadas para esta app; los permisos Wi‑Fi/Móvil siguen siendo independientes."
        AppCompatibilityMode.EXCLUDED -> if (english)
            "SIN FIREWALL: the app leaves HYDRA/VPN; HYDRA does not filter its traffic and Wi‑Fi/Mobile firewall switches do not apply."
        else
            "SIN FIREWALL: la app sale de HYDRA/VPN; HYDRA no filtra su tráfico y los controles Wi‑Fi/Móvil del firewall no aplican."
        AppCompatibilityMode.ESSENTIAL -> if (english)
            "PERMISSIVE: the app remains inside HYDRA; Wi‑Fi=${if (wifi) "ON" else "OFF"}, Mobile=${if (mobile) "ON" else "OFF"}; compatibility layers are relaxed and strong security remains active."
        else
            "PERMISIVO: la app permanece dentro de HYDRA; Wi‑Fi=${if (wifi) "ACTIVO" else "BLOQUEADO"}, Móvil=${if (mobile) "ACTIVO" else "BLOQUEADO"}; se relaja compatibilidad y se mantiene la seguridad fuerte."
        AppCompatibilityMode.ESSENTIAL_COMPAT -> if (english)
            "PERMISSIVE-COMPAT: diagnostic mode inside HYDRA; optional domain/QUIC filtering is bypassed temporarily while Wi‑Fi/Mobile rules and strong threat protection remain active."
        else
            "PERMISIVO-COMPAT: diagnóstico dentro de HYDRA; se saltea temporalmente el filtrado opcional de dominios/QUIC mientras siguen las reglas Wi‑Fi/Móvil y la protección fuerte contra amenazas."
        AppCompatibilityMode.NORMAL -> when {
            trusted && !explicit -> if (english)
                "APP DE CONFIANZA: automatic allow for selected trusted-source apps; strong security controls still apply."
            else
                "APP DE CONFIANZA: permiso automático para apps de origen confiable seleccionadas; la seguridad fuerte sigue activa."
            wifi && mobile -> if (english)
                "PERMITIR: Wi‑Fi and mobile are allowed through HYDRA; normal filtering and threat protection remain active."
            else
                "PERMITIR: Wi‑Fi y datos móviles pasan por HYDRA; el filtrado normal y la protección contra amenazas siguen activos."
            wifi -> if (english)
                "SOLO WI‑FI: Wi‑Fi is allowed through HYDRA; mobile data is blocked for this app."
            else
                "SOLO WI‑FI: Wi‑Fi pasa por HYDRA; los datos móviles quedan bloqueados para esta app."
            mobile -> if (english)
                "SOLO DATOS MÓVILES: mobile is allowed through HYDRA; Wi‑Fi is blocked for this app."
            else
                "SOLO DATOS MÓVILES: los datos móviles pasan por HYDRA; Wi‑Fi queda bloqueado para esta app."
            else -> if (english)
                "BLOQUEADA: Wi‑Fi and mobile are blocked; because there is no rule, the next network attempt will ask you."
            else
                "BLOQUEADA: Wi‑Fi y datos móviles están bloqueados; como no hay regla, el próximo intento de red preguntará."
        }
    }
}

private fun appRulePolicyColor(
    compatibilityExcluded: Boolean,
    wifiAllowed: Boolean,
    mobileAllowed: Boolean
): Color {
    return when {
        compatibilityExcluded -> Color(0xFF123B66) // SIN FIREWALL
        wifiAllowed && mobileAllowed -> Color(0xFF2E7D32) // both networks
        wifiAllowed || mobileAllowed -> Color(0xFFB8860B) // exactly one network
        else -> Color(0xFFC62828) // neither network
    }
}

@Composable
private fun AppRuleRow(
    app: AppEntry,
    wifiAllowed: Boolean,
    mobileAllowed: Boolean,
    explicitRule: Boolean,
    autoEssential: Boolean,
    userEssential: Boolean,
    customized: Boolean,
    trustedAutoAllowed: Boolean,
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
    onCompatibility: () -> Unit
) {
    val context = LocalContext.current
    val policyColor = appRulePolicyColor(compatibilityExcluded, wifiAllowed, mobileAllowed)
    Column(Modifier.fillMaxWidth().clickable(onClick = onDetails).padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            AppIcon(app, Modifier.size(32.dp))
            Spacer(Modifier.width(7.dp))
            Column(Modifier.weight(1f).padding(end = 4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(app.label, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    TextButton(onClick = onFavorite, modifier = Modifier.height(24.dp).width(24.dp), contentPadding = PaddingValues(0.dp)) { Text(if (favorite) "★" else "☆", fontSize = 16.sp) }
                }
                Text("${app.packageName} · UID ${app.uid}", style = MaterialTheme.typography.labelSmall, fontSize = 8.5.sp, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurfaceVariant)
                val sharedCount = remember(app.uid) { runCatching { context.packageManager.getPackagesForUid(app.uid)?.size ?: 0 }.getOrDefault(0) }
                if (sharedCount > 1) Text(if (AppSettings(context).language == AppLanguage.EN) "UID compartido" else "UID compartido", style = MaterialTheme.typography.labelSmall, fontSize = 7.5.sp, color = MaterialTheme.colorScheme.tertiary)
                Text(
                    when {
                        customized -> if (AppSettings(context).language == AppLanguage.EN) "CUSTOM · PROTECTIONS" else "PERSONALIZADO · PROTECCIONES"
                        userEssential && AppCompatibilityPolicyStore.getMode(app.packageName) == AppCompatibilityMode.ESSENTIAL_COMPAT -> if (AppSettings(context).language == AppLanguage.EN) "ESSENTIAL-COMPAT · DIAGNOSTIC" else "ESENCIAL-COMPAT · DIAGNÓSTICO"
                        userEssential -> if (AppSettings(context).language == AppLanguage.EN) "PERMISSIVE · FLEXIBLE FILTERS" else "PERMISIVO · FILTROS FLEXIBLES"
                        explicitRule -> if (AppSettings(context).language == AppLanguage.EN) "EXPLICIT RULE" else "REGLA EXPLÍCITA"
                        trustedAutoAllowed -> if (AppSettings(context).language == AppLanguage.EN) "TRUSTED APP · AUTO ALLOW" else "APP DE CONFIANZA · AUTO-PERMITIDA"
                        autoEssential -> if (AppSettings(context).language == AppLanguage.EN) "SYSTEM CORE · AUTO ALLOW" else "SISTEMA CENTRAL · AUTO-PERMITIDO"
                        else -> if (AppSettings(context).language == AppLanguage.EN) "NO RULE · DEFAULT BLOCK" else "SIN REGLA · BLOQUEADA POR DEFECTO"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    fontSize = 7.5.sp,
                    color = policyColor
                )
                val language = AppSettings(context).language
                val ruleMode = when {
                    compatibilityExcluded -> AppCompatibilityMode.EXCLUDED
                    customized -> AppCompatibilityMode.CUSTOM
                    AppCompatibilityPolicyStore.getMode(app.packageName) == AppCompatibilityMode.ESSENTIAL_COMPAT -> AppCompatibilityMode.ESSENTIAL_COMPAT
                    userEssential -> AppCompatibilityMode.ESSENTIAL
                    else -> AppCompatibilityMode.NORMAL
                }
                val en = language == AppLanguage.EN
                // Texto corto para la fila (la versión larga hacía 3 líneas y la lista mostraba solo dos apps).
                val ruleDetail = if (ruleMode == AppCompatibilityMode.NORMAL) when {
                    trustedAutoAllowed && !explicitRule -> if (en) "TRUSTED APP · automatic allow" else "APP DE CONFIANZA · permiso automático"
                    wifiAllowed && mobileAllowed -> if (en) "ALLOW · Wi‑Fi and mobile" else "PERMITIR · Wi‑Fi y móvil"
                    wifiAllowed -> if (en) "WI‑FI ONLY · mobile blocked" else "SOLO WI‑FI · móvil bloqueado"
                    mobileAllowed -> if (en) "MOBILE ONLY · Wi‑Fi blocked" else "SOLO MÓVIL · Wi‑Fi bloqueado"
                    explicitRule -> if (en) "BLOCKED · Wi‑Fi and mobile" else "BLOQUEADA · Wi‑Fi y móvil"
                    else -> if (en) "BLOCKED · will ask on next connection" else "BLOQUEADA · preguntará al conectar"
                } else describeAppPolicy(ruleMode, wifiAllowed, mobileAllowed, explicitRule, trustedAutoAllowed, en).substringBefore(';')
                Text(
                    ruleDetail,
                    style = MaterialTheme.typography.labelSmall,
                    fontSize = 7.5.sp,
                    color = policyColor,
                    maxLines = 2,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
                if (app.isSystem) Text(tr(context, "system").uppercase(), style = MaterialTheme.typography.labelSmall, fontSize = 8.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.width(6.dp))
            Column(horizontalAlignment = Alignment.End) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(tr(context, "wifi"), fontSize = 9.sp); Spacer(Modifier.width(3.dp))
                    Switch(checked = wifiAllowed, enabled = !compatibilityExcluded, onCheckedChange = onWifiChanged, modifier = Modifier.height(24.dp).scale(0.72f))
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(tr(context, "mobile"), fontSize = 9.sp); Spacer(Modifier.width(3.dp))
                    Switch(checked = mobileAllowed, enabled = !compatibilityExcluded, onCheckedChange = onMobileChanged, modifier = Modifier.height(24.dp).scale(0.72f))
                }
            }
        }
        Row(
            Modifier
                .fillMaxWidth()
                .padding(top = 2.dp)
                .height(32.dp),
            horizontalArrangement = Arrangement.End,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .height(30.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .background(if (customized) policyColor.copy(alpha = 0.14f) else MaterialTheme.colorScheme.surfaceVariant)
                    .clickable(onClick = onCustom)
                    .padding(horizontal = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (customized) "PERSONALIZADO ✓" else "PERSONALIZADO",
                    fontSize = 8.5.sp,
                    color = if (customized) policyColor else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    softWrap = false
                )
            }
            Spacer(Modifier.width(5.dp))
            Box(
                modifier = Modifier
                    .height(30.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .background(if (userEssential) policyColor.copy(alpha = 0.14f) else MaterialTheme.colorScheme.surfaceVariant)
                    .clickable(onClick = if (userEssential) onRemoveEssential else onMakeEssential)
                    .padding(horizontal = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (userEssential) "PERMISIVO ✓" else "PERMISIVO",
                    fontSize = 9.sp,
                    color = if (userEssential) policyColor else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    softWrap = false
                )
            }
            Spacer(Modifier.width(5.dp))
            Box(
                modifier = Modifier
                    .height(30.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .background(if (compatibilityExcluded) Color(0xFF123B66) else MaterialTheme.colorScheme.surfaceVariant)
                    .clickable(onClick = onCompatibility)
                    .padding(horizontal = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (compatibilityExcluded) "SIN FIREWALL ✓" else "SIN FIREWALL",
                    fontSize = 8.sp,
                    color = if (compatibilityExcluded) Color(0xFFEAF4FF) else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    softWrap = false
                )
            }
            Box(
                modifier = Modifier
                    .height(30.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .clickable(onClick = onDetails)
                    .padding(horizontal = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (AppSettings(context).language == AppLanguage.EN) "Detalles" else "Detalles",
                    fontSize = 10.sp,
                    maxLines = 1,
                    softWrap = false
                )
            }
            Spacer(Modifier.width(4.dp))
            Box(
                modifier = Modifier
                    .height(30.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .clickable(onClick = onSchedule)
                    .padding(horizontal = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (scheduleEnabled) tr(context, "schedule_short_active") else tr(context, "schedule_short"),
                    fontSize = 10.sp,
                    maxLines = 1,
                    softWrap = false
                )
            }
        }
    }
}

private const val HYDRA_REPOSITORY_URL = "https://github.com/hydraroot/Hydra_Firewall"
private const val HYDRA_LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"
private const val CAFECITO_URL = "https://cafecito.app/hydraroot"

@Composable
private fun TrafficAnalyzerScreen(context: Context) {
    val english = AppSettings(context).language == AppLanguage.EN
    var enabled by remember { mutableStateOf(TrafficAnalyzerStore.isEnabled()) }
    var events by remember { mutableStateOf(TrafficAnalyzerStore.snapshot()) }
    var filter by remember { mutableStateOf("ALL") }
    var search by remember { mutableStateOf("") }
    var selectedEvent by remember { mutableStateOf<TrafficAnalyzerStore.Event?>(null) }
    val ipBlockStore = remember { IpBlockStore(context.applicationContext) }
    var blockedIps by remember { mutableStateOf(ipBlockStore.getBlocked().toSet()) }

    LaunchedEffect(enabled) {
        while (enabled) {
            events = TrafficAnalyzerStore.snapshot()
            delay(700)
        }
    }

    fun matchesSearch(e: TrafficAnalyzerStore.Event): Boolean {
        val q = search.trim().lowercase(Locale.US)
        if (q.isEmpty()) return true
        val text = listOfNotNull(e.packageName, e.domain, e.destination, e.protocol, e.kind, e.port.toString()).joinToString(" ").lowercase(Locale.US)
        return text.contains(q)
    }

    val filtered = events.filter { e ->
        val typeOk = when (filter) {
            "APP" -> !e.packageName.isNullOrBlank()
            "DNS" -> e.protocol == "DNS"
            "BLOCKED" -> e.kind.contains("BLOCK", true)
            else -> true
        }
        typeOk && matchesSearch(e)
    }

    val totalBytes = filtered.sumOf { it.bytes.toLong() }
    val sentBytes = filtered.filter { it.kind == "C2S_DATA" }.sumOf { it.bytes.toLong() }
    val receivedBytes = filtered.filter { it.kind == "S2C_DATA" }.sumOf { it.bytes.toLong() }
    val dnsCount = filtered.count { it.protocol == "DNS" }
    val blockedCount = filtered.count { it.kind.contains("BLOCK", true) }
    val tcpCount = filtered.count { it.protocol == "TCP" }
    val udpCount = filtered.count { it.protocol == "UDP" }
    val quicCount = filtered.count { it.protocol == "UDP" && it.port == 443 }

    val appCounts = filtered.filter { !it.packageName.isNullOrBlank() }
        .groupingBy { it.packageName!! }.eachCount().entries.sortedByDescending { it.value }.take(12)
    val domainCounts = filtered.filter { !it.domain.isNullOrBlank() }
        .groupingBy { it.domain!! }.eachCount().entries.sortedByDescending { it.value }.take(12)
    val endpointCounts = filtered.filter { it.protocol != "DNS" }
        .groupingBy { "${it.destination}:${it.port}" }.eachCount().entries.sortedByDescending { it.value }.take(12)

    fun appLabel(pkg: String?): String {
        if (pkg.isNullOrBlank()) return if (english) "Unknown app" else "Aplicación desconocida"
        return runCatching {
            val info = context.packageManager.getApplicationInfo(pkg, 0)
            context.packageManager.getApplicationLabel(info).toString()
        }.getOrDefault(pkg)
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 10.dp, vertical = 6.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Column(Modifier.weight(1f)) {
                Text(if (english) "Network analyzer" else "Analizador de red", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(
                    if (english) "Live metadata: apps, DNS, destinations and traffic. No payloads are stored."
                    else "Metadatos en vivo: apps, DNS, destinos y tráfico. No se guardan contenidos.",
                    fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (english) "CAPTURE" else "CAPTURA", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.width(4.dp))
                Switch(checked = enabled, onCheckedChange = {
                    enabled = it
                    TrafficAnalyzerStore.setEnabled(context, it)
                    events = emptyList()
                    selectedEvent = null
                }, modifier = Modifier.height(28.dp).scale(0.82f))
            }
        }

        Spacer(Modifier.height(7.dp))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            listOf(
                "ALL" to if (english) "All" else "Todo",
                "APP" to if (english) "Apps" else "Apps",
                "DNS" to "DNS",
                "BLOCKED" to if (english) "Blocked" else "Bloqueados"
            ).forEach { (key, label) ->
                HydraChoiceButton(filter == key, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick = { filter = key }, modifier = Modifier.height(30.dp))
            }
            HydraChoiceButton(false, if (english) "Clear" else "Borrar", Color(0xFFB83A46), Color.White, onClick = {
                TrafficAnalyzerStore.clear(); events = emptyList(); selectedEvent = null
            }, modifier = Modifier.height(30.dp))
        }

        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            singleLine = true,
            label = { Text(if (english) "Search app, domain, IP or port" else "Buscar app, dominio, IP o puerto") },
            modifier = Modifier.fillMaxWidth(),
            textStyle = LocalTextStyle.current.copy(fontSize = 12.sp)
        )

        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            AnalyzerMetric(if (english) "Events" else "Eventos", filtered.size.toString())
            AnalyzerMetric("DNS", dnsCount.toString())
            AnalyzerMetric(if (english) "Blocked" else "Bloqueados", blockedCount.toString())
            AnalyzerMetric("TCP/UDP", "$tcpCount/$udpCount")
            AnalyzerMetric("QUIC", quicCount.toString())
        }
        Spacer(Modifier.height(5.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            AnalyzerMetric("↑", formatAnalyzerBytes(sentBytes))
            AnalyzerMetric("↓", formatAnalyzerBytes(receivedBytes))
            AnalyzerMetric(if (english) "Total" else "Total", formatAnalyzerBytes(totalBytes))
        }

        if (!enabled) {
            Spacer(Modifier.height(10.dp))
            AnalyzerSection(if (english) "Ready" else "Listo") {
                Text(if (english) "Enable Capture and use the phone normally. Hydra will show activity here in real time."
                     else "Activá Captura y usá el teléfono normalmente. Hydra mostrará la actividad en tiempo real.", fontSize = 12.sp)
            }
        } else {
            AnalyzerSection(if (english) "Applications" else "Aplicaciones") {
                if (appCounts.isEmpty()) Text("—", fontSize = 12.sp)
                appCounts.forEach { (pkg, count) ->
                    val appEvents = filtered.filter { it.packageName == pkg }
                    val bytes = appEvents.sumOf { it.bytes.toLong() }
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(appLabel(pkg), fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
                        Text("${formatAnalyzerBytes(bytes)}  •  $count", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            AnalyzerSection(if (english) "DNS domains" else "Dominios DNS") {
                if (domainCounts.isEmpty()) Text("—", fontSize = 12.sp)
                domainCounts.forEach { (domain, count) -> AnalyzerLine(domain, count.toString()) }
            }

            AnalyzerSection(if (english) "Top destinations" else "Principales destinos") {
                if (endpointCounts.isEmpty()) Text("—", fontSize = 12.sp)
                endpointCounts.forEach { (endpoint, count) -> AnalyzerLine(endpoint, count.toString()) }
            }

            AnalyzerSection(if (english) "Live activity" else "Actividad en vivo") {
                filtered.take(50).forEach { e ->
                    val app = appLabel(e.packageName)
                    val status = if (e.kind.contains("BLOCK", true)) " ⛔" else ""
                    Row(
                        Modifier.fillMaxWidth().clickable { selectedEvent = e }.padding(vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("${e.time}  $app$status", fontSize = 10.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            Text("${e.protocol}  ${e.destination}:${e.port}  ${e.kind}${if (e.bytes > 0) "  ${formatAnalyzerBytes(e.bytes.toLong())}" else ""}", fontSize = 9.sp, maxLines = 1, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        selectedEvent?.let { e ->
            AnalyzerSection(if (english) "Connection details" else "Detalles de conexión") {
                Text(if (english) "App: ${appLabel(e.packageName)}" else "App: ${appLabel(e.packageName)}", fontSize = 11.sp)
                Text("Package: ${e.packageName ?: "—"}", fontSize = 10.sp)
                Text("${e.protocol}  ${e.destination}:${e.port}", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text("${e.kind}  ${formatAnalyzerBytes(e.bytes.toLong())}", fontSize = 10.sp)
                if (!e.domain.isNullOrBlank()) Text("DNS: ${e.domain}", fontSize = 10.sp)
                if (e.destination != "?" && runCatching { java.net.InetAddress.getByName(e.destination) }.isSuccess) {
                    val isBlocked = blockedIps.contains(e.destination)
                    val isException = ipBlockStore.isAllowedForUid(e.uid, e.destination)
                    val isPolicyBlocked = e.kind.contains("BLOCK", true)
                    Spacer(Modifier.height(5.dp))
                    val label = when {
                        isBlocked -> if (english) "Unblock IP" else "Desbloquear IP"
                        isException -> if (english) "Remove IP allow" else "Quitar permiso IP"
                        isPolicyBlocked -> if (english) "Allow IP" else "Permitir IP"
                        else -> if (english) "Block IP" else "Bloquear IP"
                    }
                    HydraChoiceButton(isBlocked || isException, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick = {
                        when {
                            isBlocked -> ipBlockStore.remove(e.destination)
                            isException -> ipBlockStore.removeAllowedForUid(e.uid, e.destination)
                            isPolicyBlocked -> ipBlockStore.allowForUid(e.uid, e.destination)
                            else -> ipBlockStore.add(e.destination)
                        }
                        blockedIps = ipBlockStore.getBlocked().toSet()
                        notifyRulesChanged(context)
                    }, modifier = Modifier.height(30.dp))
                }
            }
        }
    }
}

@Composable
private fun AnalyzerMetric(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontWeight = FontWeight.Bold, fontSize = 12.sp)
        Text(label, fontSize = 8.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AnalyzerSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(title, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 7.dp, bottom = 3.dp))
    Surface(shape = RoundedCornerShape(10.dp), tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(8.dp), content = content)
    }
    Spacer(Modifier.height(4.dp))
}

@Composable
private fun AnalyzerLine(left: String, right: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(left, fontSize = 10.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Text(right, fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 8.dp))
    }
}

private fun formatAnalyzerBytes(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / 1048576.0)
    bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "${bytes} B"
}


@Composable
private fun AboutScreen(context: Context) {
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
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "about_summary"), style = MaterialTheme.typography.bodyMedium)
                Text(tr(context, "about_features"), style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "license"), style = MaterialTheme.typography.titleSmall)
                Text(tr(context, "license_gpl"), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(HYDRA_LICENSE_URL))) }) {
                    Text(tr(context, "view_license"))
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "repository"), style = MaterialTheme.typography.titleSmall)
                Text(HYDRA_REPOSITORY_URL, style = MaterialTheme.typography.bodySmall)
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(HYDRA_REPOSITORY_URL))) }) {
                    Text(tr(context, "open_repository"))
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(tr(context, "block_ads_title"), style = MaterialTheme.typography.titleSmall)
                Text(tr(context, "block_ads_attribution"), style = MaterialTheme.typography.bodySmall)
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DomainBlockStore.SOURCE_PAGE_URL))) }) {
                    Text(DomainBlockStore.SOURCE_PAGE_URL)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Card(Modifier.fillMaxWidth()) {
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




private fun notifyRulesChanged(context: Context) {
    if (!FirewallVpnService.isRunning) return
    context.startService(Intent(context, FirewallVpnService::class.java).apply { action = FirewallVpnService.ACTION_RULES_CHANGED })
}

private fun loadNetworkApps(context: Context): List<AppEntry> {
    val pm = context.packageManager
    return runCatching {
        pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).asSequence()
            .filter { it.packageName != context.packageName }
            .filter { it.requestedPermissions?.contains(Manifest.permission.INTERNET) == true }
            .mapNotNull { p ->
                val info = p.applicationInfo ?: return@mapNotNull null
                AppEntry(
                    label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(p.packageName),
                    packageName = p.packageName,
                    uid = info.uid,
                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                    processName = info.processName ?: p.packageName
                )
            }.distinctBy { "${it.packageName}:${it.uid}" }.sortedBy { it.label.lowercase() }.toList()
    }.getOrDefault(emptyList())
}

private const val byteOrderMark = "\uFEFF"

private fun buildHistoryCsv(records: List<ConnectionHistory.Record>): String {
    val sb = StringBuilder()
    sb.append("id,timestamp,hora,uid,aplicacion,protocolo,red,origen,destino,dominio,resultado,evento,repeticiones\n")
    records.forEach { r ->
        val host = extractHost(r.destination)
        val domain = DomainResolver.cached(host).orEmpty()
        val values = listOf(
            r.id.toString(), r.timestamp.toString(), r.time, r.uid.toString(), r.packageName.orEmpty(),
            r.protocol, r.network.displayName, r.source, r.destination, domain, if (r.allowed) "PERMITIDO" else "BLOQUEADO", r.event, r.repeatCount.toString()
        )
        sb.append(values.joinToString(",") { csvEscape(it) }).append('\n')
    }
    return sb.toString()
}

private fun csvEscape(value: String): String = "\"${value.replace("\"", "\"\"")}\""

private fun formatTrafficMb(mb: Float): String {
    val bytes = (mb.toDouble() * 1024.0 * 1024.0).coerceAtLeast(0.0)
    return when {
        bytes < 1024.0 -> String.format(java.util.Locale.US, "%.0f B", bytes)
        bytes < 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        bytes < 1024.0 * 1024.0 * 1024.0 -> String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
    bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
}


@Composable
private fun SecuritySettingsSection(context: Context, lockStore: LockStore, onChanged: () -> Unit) {
    var enabled by remember { mutableStateOf(lockStore.enabled && lockStore.configured) }
    var biometric by remember { mutableStateOf(lockStore.biometricEnabled) }
    var showPinDialog by remember { mutableStateOf(false) }
    var showChangePinDialog by remember { mutableStateOf(false) }
    var currentPin by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var pin2 by remember { mutableStateOf("") }
    var pinError by remember { mutableStateOf(false) }
    var cryptoBusy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    SettingSwitchRow(tr(context, "lock_app"), tr(context, "lock_sub"), enabled) { checked ->
        if (checked) {
            if (lockStore.configured) {
                lockStore.enabled = true
                enabled = true
            } else {
                pin = ""; pin2 = ""; pinError = false; showPinDialog = true
            }
        } else {
            lockStore.enabled = false
            enabled = false
            onChanged()
        }
    }

    SettingSwitchRow(tr(context, "use_fingerprint"), tr(context, "fingerprint_sub"), biometric) { checked ->
        biometric = checked
        lockStore.biometricEnabled = checked
    }

    if (enabled && lockStore.configured) {
        TextButton(onClick = { currentPin = ""; pin = ""; pin2 = ""; pinError = false; showChangePinDialog = true }) {
            Text(tr(context, "change_pin"))
        }
    }

    if (showPinDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showPinDialog = false },
            title = { Text(if (AppSettings(context).language == AppLanguage.EN) "Create PIN" else "Crear PIN") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(pin, { if (it.length <= 8 && it.all(Char::isDigit)) { pin = it; pinError = false } }, singleLine = true,
                        label = { Text("PIN (4-8)") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin2, { if (it.length <= 8 && it.all(Char::isDigit)) { pin2 = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language == AppLanguage.EN) "Repeat PIN" else "Repetir PIN") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    if (pinError) Text(if (AppSettings(context).language == AppLanguage.EN) "PINs do not match or are invalid." else "Los PIN no coinciden o no son válidos.", color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (cryptoBusy) return@TextButton
                    if (pin.length in 4..8 && pin == pin2) {
                        val newPin = pin
                        cryptoBusy = true
                        scope.launch(Dispatchers.Default) {
                            lockStore.setPin(newPin)
                            withContext(Dispatchers.Main) {
                                cryptoBusy = false
                                lockStore.enabled = true
                                enabled = true
                                showPinDialog = false
                            }
                        }
                    } else pinError = true
                }, enabled = !cryptoBusy) { Text(if (cryptoBusy) (if (AppSettings(context).language == AppLanguage.EN) "Saving..." else "Guardando...") else tr(context, "save")) }
            },
            dismissButton = { TextButton(onClick = { showPinDialog = false }) { Text(tr(context, "cancel")) } }
        )
    }

    if (showChangePinDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showChangePinDialog = false },
            title = { Text(tr(context, "change_pin")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(currentPin, { if (it.length <= 8 && it.all(Char::isDigit)) { currentPin = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language == AppLanguage.EN) "Current PIN" else "PIN actual") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin, { if (it.length <= 8 && it.all(Char::isDigit)) { pin = it; pinError = false } }, singleLine = true,
                        label = { Text("PIN (4-8)") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin2, { if (it.length <= 8 && it.all(Char::isDigit)) { pin2 = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language == AppLanguage.EN) "Repeat PIN" else "Repetir PIN") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    if (pinError) Text(if (AppSettings(context).language == AppLanguage.EN) "Current PIN invalid, new PINs do not match, or PIN is temporarily locked." else "PIN actual incorrecto, los nuevos PIN no coinciden o el PIN está temporalmente bloqueado.", color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (cryptoBusy) return@TextButton
                    if (currentPin.length in 4..8 && pin.length in 4..8 && pin2.length in 4..8) {
                        val oldPin = currentPin
                        val newPin = pin
                        if (newPin != pin2) {
                            pinError = true
                            return@TextButton
                        }
                        cryptoBusy = true
                        scope.launch(Dispatchers.Default) {
                            val verified = lockStore.verifyPin(oldPin)
                            if (verified) lockStore.setPin(newPin)
                            withContext(Dispatchers.Main) {
                                cryptoBusy = false
                                if (verified) showChangePinDialog = false else pinError = true
                            }
                        }
                    } else pinError = true
                }, enabled = !cryptoBusy && currentPin.length in 4..8 && pin.length in 4..8 && pin2.length in 4..8) { Text(if (cryptoBusy) (if (AppSettings(context).language == AppLanguage.EN) "Saving..." else "Guardando...") else tr(context, "save")) }
            },
            dismissButton = { TextButton(onClick = { showChangePinDialog = false }) { Text(tr(context, "cancel")) } }
        )
    }
}

@Composable
private fun ScheduleEditor(context: Context, initial: RuleStore.Schedule, onChanged: (RuleStore.Schedule) -> Unit) {
    var schedule by remember(initial) { mutableStateOf(initial) }
    val english = AppSettings(context).language == AppLanguage.EN
    val dayLabels = if (english) listOf("M", "T", "W", "T", "F", "S", "S") else listOf("L", "M", "X", "J", "V", "S", "D")
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        SettingSwitchRow(tr(context, "blocked_by_schedule"), tr(context, "schedule_sub"), schedule.enabled) {
            schedule = schedule.copy(enabled = it)
            onChanged(schedule)
        }
        if (schedule.enabled) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                TimeStepper(context, tr(context, "from"), schedule.startMinutes) { v -> schedule = schedule.copy(startMinutes = v); onChanged(schedule) }
                TimeStepper(context, tr(context, "to"), schedule.endMinutes) { v -> schedule = schedule.copy(endMinutes = v); onChanged(schedule) }
            }
            Text(tr(context, "days"), style = MaterialTheme.typography.labelSmall)
            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                dayLabels.forEachIndexed { i, label ->
                    val selected = (schedule.daysMask and (1 shl i)) != 0
                    HydraChoiceButton(selected, label, Color(0xFFE3D0FF), Color(0xFF241A34), onClick = {
                        val mask = if (selected) schedule.daysMask and (1 shl i).inv() else schedule.daysMask or (1 shl i)
                        schedule = schedule.copy(daysMask = mask)
                        onChanged(schedule)
                    }, modifier=Modifier.height(30.dp), fontSize=11.sp)
                }
            }
            Text(tr(context, "schedule_all_day"), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun TimeStepper(context: Context, label: String, minutes: Int, onChange: (Int) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.width(142.dp)) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
            Text(label, style = MaterialTheme.typography.labelSmall)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
                TextButton(
                    onClick = { onChange((minutes - 30 + 1440) % 1440) },
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(30.dp)
                ) { Text("−", fontSize = 18.sp) }
                Text("%02d:%02d".format(minutes / 60, minutes % 60), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.width(50.dp), textAlign = TextAlign.Center)
                TextButton(
                    onClick = { onChange((minutes + 30) % 1440) },
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(30.dp)
                ) { Text("+", fontSize = 18.sp) }
            }
        }
    }
}
