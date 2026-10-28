package com.hydra.firewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import androidx.core.app.NotificationCompat
import com.hydra.firewall.MainActivity
import com.hydra.firewall.security.ThreatSignatureStore
import com.hydra.firewall.security.ThreatSignatureUpdater
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * HYDRA VPN service: IPv4 + basic IPv6 TCP/UDP forwarding with basic local ICMPv6 handling and per-UID rules.
 *
 * TUN reading is performed once in this service. Packets are parsed once at
 * the IP layer and dispatched to the corresponding TCP or UDP selector engine.
 * IPv4 fragments are rejected safely; IPv6 fragments are reassembled with strict bounds.
 * IPv6 link-local/multicast control traffic is intentionally left outside the VPN
 * route so Android and the physical interface can perform NDP/router discovery directly.
 */
class FirewallVpnService : VpnService() {
    companion object {
        private const val TAG = "FirewallVpnService"
        private const val CHANNEL_ID = "firewall_channel"
        private const val NOTIFICATION_ID = 1
        private const val KEY_DESIRED_RUNNING = "desired_running"

        const val ACTION_START = "com.hydra.firewall.action.START"
        const val ACTION_STOP = "com.hydra.firewall.action.STOP"
        const val ACTION_RULES_CHANGED = "com.hydra.firewall.action.RULES_CHANGED"
        const val ACTION_COMPATIBILITY_CHANGED = "com.hydra.firewall.action.COMPATIBILITY_CHANGED"
        const val ACTION_LIVE_TEST_MODE = "com.hydra.firewall.action.LIVE_TEST_MODE"
        private const val EXTRA_LIVE_TEST_ENABLED = "live_test_enabled"


        const val VPN_ADDRESS = "10.0.0.2"
        const val VPN_PREFIX_LENGTH = 32
        const val VPN_IPV6_ADDRESS = "fd00:6572:1::2"
        const val VPN_IPV6_PREFIX_LENGTH = 128

        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        var activeTcpSessions: Int = 0
            private set

        @Volatile
        var activeUdpSessions: Int = 0
            private set

        @Volatile
        var currentNetworkKind: NetworkKind = NetworkKind.NONE
            private set

        @Volatile
        var configuredDnsServers: List<String> = emptyList()
            private set

        @Volatile
        var liveTestMode: Boolean = false
            private set


        /**
         * Requests a controlled in-place VPN restart with HYDRA's own package
         * either included in the tunnel (enabled=true) or excluded again
         * (enabled=false). The request is handled by FirewallVpnService itself
         * so the stop/start sequence cannot race with stopSelf()/onDestroy().
         */
        fun setLiveTestMode(context: Context, enabled: Boolean) {
            if (liveTestMode == enabled && isRunning) return
            val appContext = context.applicationContext
            val intent = Intent(appContext, FirewallVpnService::class.java).apply {
                action = ACTION_LIVE_TEST_MODE
                putExtra(EXTRA_LIVE_TEST_ENABLED, enabled)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appContext.startForegroundService(intent)
            } else {
                appContext.startService(intent)
            }
        }

        @Volatile
        var currentRoaming: Boolean = false
            private set

        @Volatile
        var lastPacketAt: Long = 0L
            private set

        @Volatile
        var alwaysOnEnabled: Boolean = false
            private set

        @Volatile
        var lockdownEnabled: Boolean = false
            private set
    }

    private val running = AtomicBoolean(false)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunInputPfd: ParcelFileDescriptor? = null
    private var tunOutputPfd: ParcelFileDescriptor? = null
    private var tunReaderThread: Thread? = null
    private val servicePrefs by lazy { getSharedPreferences("firewall_service", Context.MODE_PRIVATE) }

    private fun setDesiredRunning(value: Boolean) {
        servicePrefs.edit().putBoolean(KEY_DESIRED_RUNNING, value).apply()
        runCatching {
            createDeviceProtectedStorageContext()
                .getSharedPreferences("firewall_service_device", Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_DESIRED_RUNNING, value).apply()
        }
    }

    private lateinit var uidResolver: UidResolver
    private lateinit var ruleStore: RuleStore
    private lateinit var ruleEngine: RuleEngine
    private lateinit var tcpEngine: TcpForwardingEngine
    private lateinit var udpEngine: UdpForwardingEngine
    private lateinit var ipv6TcpEngine: Ipv6TcpForwardingEngine
    private lateinit var ipv6UdpEngine: Ipv6UdpForwardingEngine
    private lateinit var networkMonitor: NetworkStateMonitor
    private lateinit var tunWriter: TunPacketWriter
    private lateinit var quarantineManager: QuarantineManager
    private lateinit var dozeAnomalyMonitor: DozeAnomalyMonitor
    private var lifecycleWatcher: AppLifecycleWatcher? = null
    private val policyHandler = Handler(Looper.getMainLooper())
    private val scheduleRefreshRunnable = object : Runnable {
        override fun run() {
            if (!running.get()) return
            if (::tcpEngine.isInitialized) tcpEngine.refreshPolicies()
            if (::udpEngine.isInitialized) udpEngine.refreshPolicies()
            if (::ipv6TcpEngine.isInitialized) ipv6TcpEngine.refreshPolicies()
            if (::ipv6UdpEngine.isInitialized) ipv6UdpEngine.refreshPolicies()
            if (::dozeAnomalyMonitor.isInitialized) dozeAnomalyMonitor.poll()
            if (::uidResolver.isInitialized) uidResolver.purgeExpired()
            policyHandler.postDelayed(this, 30_000L)
        }
    }

    override fun onCreate() {
        super.onCreate()
        uidResolver = UidResolver(this)
        ruleStore = RuleStore(this)
        ruleEngine = RuleEngine(ruleStore, this)
        DiagnosticLogger.init(this)
        ConnectionHistory.init(this)
        TrafficAnalyzerStore.init(this)
        TrafficStatsStore.init(this)
        NotificationHelper.init(this)
        DecisionRequestManager.restorePendingNotifications(this)
        DomainBlockStore.init(this)
        AppCompatibilityPolicyStore.init(this)
        ThreatSignatureStore.init(this)
        ThreatSignatureUpdater.scheduleDaily(this)
        ThreatSignatureUpdater.updateIfDue(this)
        TlsFingerprintStore.init(this)
        AppNetworkProfileStore.init(this)
        ServiceTamperMonitor.init(this)
        quarantineManager = QuarantineManager(this)
        dozeAnomalyMonitor = DozeAnomalyMonitor(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createNotificationChannel()
        }
        lifecycleWatcher = AppLifecycleWatcher(this, quarantineManager) {
            if (running.get()) {
                tcpEngine.refreshPolicies(); udpEngine.refreshPolicies()
                ipv6TcpEngine.refreshPolicies(); ipv6UdpEngine.refreshPolicies()
            }
        }.also { it.register() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                setDesiredRunning(false)
                ServiceTamperMonitor.markIntentionalStop()
                stopVpn()
                START_NOT_STICKY
            }
            ACTION_RULES_CHANGED -> {
                if (running.get()) {
                    tcpEngine.refreshPolicies()
                    udpEngine.refreshPolicies()
                    ipv6TcpEngine.refreshPolicies()
                    ipv6UdpEngine.refreshPolicies()
                } else {
                    DiagnosticLogger.logServiceEvent("RULES_CHANGED_IGNORED_VPN_STOPPED")
                }
                START_NOT_STICKY
            }
            ACTION_COMPATIBILITY_CHANGED -> {
                val pkg = intent?.getStringExtra(AppCompatibilityController.packageExtraKey()).orEmpty()
                val mode = intent?.getStringExtra(AppCompatibilityController.modeExtraKey()).orEmpty()
                DiagnosticLogger.logServiceEvent(
                    "COMPATIBILITY_RESTART_REQUEST package=$pkg mode=$mode running=${isRunning}"
                )
                // Do not use ACTION_STOP/ACTION_START here. Those actions toggle
                // the desired-running flag and can race with the UI. Keep the
                // service alive and rebuild the TUN in place so the new
                // addDisallowedApplication() set is applied atomically.
                setDesiredRunning(true)
                if (running.get()) {
                    DiagnosticLogger.logServiceEvent("COMPATIBILITY_RESTART_BEGIN package=$pkg mode=$mode")
                    stopVpn(stopService = false)
                }
                startVpn()
                DiagnosticLogger.logServiceEvent("COMPATIBILITY_RESTART_READY package=$pkg mode=$mode running=${isRunning}")
                START_STICKY
            }
            ACTION_LIVE_TEST_MODE -> {
                val enabled = intent?.getBooleanExtra(EXTRA_LIVE_TEST_ENABLED, false) ?: false
                DiagnosticLogger.logServiceEvent("LIVE_TEST_REQUEST enabled=$enabled running=${isRunning}")
                if (enabled) {
                    // Remove any stale prompt that may have been queued for HYDRA
                    // itself just before the controlled VPN restart.
                    DecisionRequestManager.cancelUid(Process.myUid())
                }
                liveTestMode = enabled
                // Keep the desired state ON for the controlled restart. Do not
                // call the old ACTION_STOP/ACTION_START pair: stopVpn() used
                // to call stopSelf(), which could race with the queued restart
                // and leave the live test waiting forever.
                setDesiredRunning(true)
                if (running.get()) {
                    DiagnosticLogger.logServiceEvent("LIVE_TEST_RESTART_BEGIN enabled=$enabled")
                    stopVpn(stopService = false)
                }
                startVpn()
                DiagnosticLogger.logServiceEvent("LIVE_TEST_RESTART_READY enabled=$enabled running=${isRunning}")
                START_STICKY
            }
            else -> {
                setDesiredRunning(true)
                startVpn()
                START_STICKY
            }
        }
    }

    /**
     * FIX148: bind upstream sockets to the currently selected physical network.
     * This complements VpnService.protect() on Android 7, where the process
     * default network can otherwise remain associated with the VPN.
     *
     * Returns true when there is no selected physical network (so callers may
     * fall back to protect-only behavior), or when the bind succeeded.
     */
    fun bindUpstreamSocketToPhysicalNetwork(socket: java.net.Socket): Boolean {
        val monitor = if (::networkMonitor.isInitialized) networkMonitor else null
        val network = monitor?.currentUnderlyingNetwork()
        if (network == null) {
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BIND_SKIPPED reason=NO_PHYSICAL_NETWORK")
            return true
        }
        return runCatching {
            network.bindSocket(socket)
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BOUND network=$network socket=TCP")
            true
        }.getOrElse {
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BIND_FAILED network=$network socket=TCP error=${it.javaClass.simpleName}:${it.message ?: ""}")
            false
        }
    }

    fun bindUpstreamSocketToPhysicalNetwork(socket: java.net.DatagramSocket): Boolean {
        val monitor = if (::networkMonitor.isInitialized) networkMonitor else null
        val network = monitor?.currentUnderlyingNetwork()
        if (network == null) {
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BIND_SKIPPED reason=NO_PHYSICAL_NETWORK socket=UDP")
            return true
        }
        return runCatching {
            network.bindSocket(socket)
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BOUND network=$network socket=UDP")
            true
        }.getOrElse {
            DiagnosticLogger.logServiceEvent("UPSTREAM_NETWORK_BIND_FAILED network=$network socket=UDP error=${it.javaClass.simpleName}:${it.message ?: ""}")
            false
        }
    }

    private fun hasUsablePhysicalIpv6(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        for (network in cm.allNetworks) {
            val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP &&
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) continue
            val lp = runCatching { cm.getLinkProperties(network) }.getOrNull() ?: continue
            if (lp.linkAddresses.any { addr ->
                    val a = addr.address
                    a is java.net.Inet6Address &&
                        !a.isLinkLocalAddress &&
                        !a.isLoopbackAddress &&
                        !a.isMulticastAddress
                }) return true
        }
        return false
    }

    private val ipv6BlockedCount = java.util.concurrent.atomic.AtomicLong(0)

    private fun startVpn() {
        if (!running.compareAndSet(false, true)) return
        val vpnDnsServers = runCatching { discoverPhysicalDnsServers() }
            .getOrDefault(listOf("1.1.1.1", "8.8.8.8"))
        ruleEngine.setConfiguredVpnDnsServers(vpnDnsServers)
        configuredDnsServers = vpnDnsServers
        ServiceTamperMonitor.clearIntentionalFlag()
        if (::quarantineManager.isInitialized) quarantineManager.syncOnStartup(this)

        val physicalIpv6 = hasUsablePhysicalIpv6() || ruleStore.blockIpv6
        val builder = Builder()
            .setSession(com.hydra.firewall.BuildConfig.BUILD_LABEL)
            .addAddress(VPN_ADDRESS, VPN_PREFIX_LENGTH)
            .addRoute("0.0.0.0", 0)
            .setMtu(1500)
            .setBlocking(true)

        if (physicalIpv6) {
            builder.addAddress(VPN_IPV6_ADDRESS, VPN_IPV6_PREFIX_LENGTH)
            builder.addRoute("2000::", 3)
            builder.addRoute("fc00::", 7)
            // NAT64 (RFC 6052 / RFC 8215): evita fuga en redes DNS64/464XLAT.
            builder.addRoute("64:ff9b::", 96)
            builder.addRoute("64:ff9b:1::", 48)
            DiagnosticLogger.logServiceEvent("VPN IPv6 ENABLED physical_ipv6=true")
        } else {
            DiagnosticLogger.logServiceEvent("VPN IPv6 DISABLED physical_ipv6=false reason=NO_GLOBAL_PHYSICAL_IPV6")
        }

        vpnDnsServers.forEach { server ->
            runCatching {
                builder.addDnsServer(server)
                DiagnosticLogger.logServiceEvent("VPN DNS configured=$server")
            }.onFailure {
                DiagnosticLogger.logServiceEvent("VPN DNS configure_failed=$server err=${it.javaClass.simpleName}")
            }
        }

        if (!liveTestMode) {
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "No se pudo excluir el propio package del túnel", e)
            }
        } else {
            DiagnosticLogger.logServiceEvent("LIVE_TEST_MODE package incluido en el tunel para autoprueba")
        }

        // Compatibility EXCLUDED mode: these apps are really kept outside the
        // local VPN. This is different from ESSENTIAL mode, which keeps the app
        // inside HYDRA and only relaxes optional filters.
        AppCompatibilityPolicyStore.excludedPackages().forEach { excludedPackage ->
            if (excludedPackage == packageName) return@forEach
            try {
                builder.addDisallowedApplication(excludedPackage)
                DiagnosticLogger.logServiceEvent("VPN_APP_EXCLUDED package=$excludedPackage reason=COMPATIBILITY_MODE")
            } catch (e: PackageManager.NameNotFoundException) {
                DiagnosticLogger.logServiceEvent("VPN_APP_EXCLUDE_SKIPPED package=$excludedPackage reason=NOT_INSTALLED")
            }
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Fallo al establecer VPN", e)
            running.set(false)
            setDesiredRunning(true)
            VpnRecoveryScheduler.schedule(this, 15_000L)
            stopSelf()
            return
        }

        if (pfd == null) {
            Log.e(TAG, "establish() devolvió null")
            running.set(false)
            setDesiredRunning(true)
            VpnRecoveryScheduler.schedule(this, 15_000L)
            stopSelf()
            return
        }

        try {
            val inPfd = ParcelFileDescriptor.dup(pfd.fileDescriptor)
            val outPfd = ParcelFileDescriptor.dup(pfd.fileDescriptor)
            val input = ParcelFileDescriptor.AutoCloseInputStream(inPfd)
            val output = ParcelFileDescriptor.AutoCloseOutputStream(outPfd)

            vpnInterface = pfd
            tunInputPfd = inPfd
            tunOutputPfd = outPfd
            tunWriter = TunPacketWriter(output)

            tcpEngine = TcpForwardingEngine(
                service = this,
                tunOut = tunWriter,
                uidResolver = uidResolver,
                ruleEngine = ruleEngine,
                initialNetwork = NetworkKind.NONE
            )
            udpEngine = UdpForwardingEngine(
                service = this,
                tunWriter = tunWriter,
                uidResolver = uidResolver,
                ruleEngine = ruleEngine,
                initialNetwork = NetworkKind.NONE
            )

            ruleEngine.setNetworkState(NetworkKind.NONE, false)
            tcpEngine.start()
            udpEngine.start()
            ipv6TcpEngine = Ipv6TcpForwardingEngine(
                service = this, tunOut = tunWriter, uidResolver = uidResolver, ruleEngine = ruleEngine, initialNetwork = NetworkKind.NONE
            )
            ipv6UdpEngine = Ipv6UdpForwardingEngine(
                service = this, tunWriter = tunWriter, uidResolver = uidResolver, ruleEngine = ruleEngine, initialNetwork = NetworkKind.NONE
            )
            ipv6TcpEngine.start()
            ipv6UdpEngine.start()

            networkMonitor = NetworkStateMonitor(this) { state ->
                currentNetworkKind = state.kind
                updateVpnUnderlyingNetwork()
                currentRoaming = state.roaming
                ruleEngine.setNetworkState(state.kind, state.roaming)
                DiagnosticLogger.logServiceEvent("NETWORK = ${state.kind.displayName} roaming=${state.roaming}")
                tcpEngine.onNetworkChanged(state.kind)
                udpEngine.onNetworkChanged(state.kind)
                ipv6TcpEngine.onNetworkChanged(state.kind)
                ipv6UdpEngine.onNetworkChanged(state.kind)
            }
            networkMonitor.start()
            updateVpnUnderlyingNetwork()

            startForegroundWithNotification()
            isRunning = true
            if (Build.VERSION.SDK_INT >= 29) {
                alwaysOnEnabled = runCatching { isAlwaysOn() }.getOrDefault(false)
                lockdownEnabled = runCatching { isLockdownEnabled() }.getOrDefault(false)
            }
            DiagnosticLogger.logServiceEvent("VPN ${com.hydra.firewall.BuildConfig.BUILD_LABEL} INICIADA")
            VpnRecoveryScheduler.markRecovered(this)

            tunReaderThread = Thread({ readTun(input) }, "FirewallTunReader").apply { start() }
        } catch (e: Exception) {
            Log.e(TAG, "No se pudo iniciar los motores TCP/UDP", e)
            running.set(false)
            if (::networkMonitor.isInitialized) {
                try { networkMonitor.stop() } catch (_: Exception) { }
            }
            if (::tcpEngine.isInitialized) {
                try { tcpEngine.stop() } catch (_: Exception) { }
            }
            if (::udpEngine.isInitialized) {
                try { udpEngine.stop() } catch (_: Exception) { }
            }
            if (::ipv6TcpEngine.isInitialized) {
                try { ipv6TcpEngine.stop() } catch (_: Exception) { }
            }
            if (::ipv6UdpEngine.isInitialized) {
                try { ipv6UdpEngine.stop() } catch (_: Exception) { }
            }
            try { tunInputPfd?.close() } catch (_: Exception) { }
            try { tunOutputPfd?.close() } catch (_: Exception) { }
            tunInputPfd = null
            tunOutputPfd = null
            try { pfd.close() } catch (_: Exception) { }
            vpnInterface = null
            currentNetworkKind = NetworkKind.NONE
            activeTcpSessions = 0
            activeUdpSessions = 0
            stopSelf()
        }
    }

    private fun readTun(input: InputStream) {
        val buffer = ByteArray(32767)
        try {
            while (running.get()) {
                val len = try {
                    input.read(buffer)
                } catch (e: IOException) {
                    if (running.get()) Log.e(TAG, "Error leyendo TUN", e)
                    break
                }
                if (len <= 0) continue
                lastPacketAt = System.currentTimeMillis()
                val packet = buffer.copyOf(len)
                dispatchTunPacket(packet)
                activeTcpSessions = tcpEngine.activeSessions() +
                        if (::ipv6TcpEngine.isInitialized) ipv6TcpEngine.activeSessions() else 0
                activeUdpSessions = udpEngine.activeSessions() +
                        if (::ipv6UdpEngine.isInitialized) ipv6UdpEngine.activeSessions() else 0
            }
        } finally {
            try { input.close() } catch (_: Exception) { }
        }
    }

    /** Parse once at the IP layer, then dispatch to the protocol-specific engine. */
    private fun dispatchTunPacket(packet: ByteArray) {
        // Interruptor "Bloquear IPv6": se descarta todo paquete IPv6 que entra al túnel (efecto inmediato,
        // sin reiniciar la VPN). Las apps reintentan por IPv4 (happy eyeballs) y pasan por los filtros IPv4.
        if (packet.isNotEmpty() && (packet[0].toInt() ushr 4) == 6 && ruleStore.blockIpv6) {
            val n = ipv6BlockedCount.incrementAndGet()
            if (n == 1L || n % 200L == 0L) DiagnosticLogger.logServiceEvent("IPV6 BLOCKED_BY_USER total=$n")
            return
        }
        when (val result = IpParser.parse(packet)) {
            is IpParser.Result.Ipv6Unsupported -> {
                DiagnosticLogger.logIpv6Unsupported(IpParser.ipv6UnsupportedCount.get())
            }
            is IpParser.Result.Ipv6ChecksumInvalid -> {
                val count = IpParser.ipv6ChecksumErrorCount.get()
                if (count == 1L || count % 50L == 0L) {
                    DiagnosticLogger.logServiceEvent("IPV6 CHECKSUM INVALID total_seen=$count")
                }
            }
            is IpParser.Result.Malformed -> {
                val count = IpParser.malformedCount.get()
                if (count == 1L || count % 100L == 0L) {
                    DiagnosticLogger.logServiceEvent("MALFORMED IP PACKET total_seen=$count")
                }
            }
            is IpParser.Result.Icmpv6 -> {
                try {
                    Icmpv6Handler.handle(result.packet, result.header, tunWriter)
                } catch (e: Exception) {
                    Log.w(TAG, "ICMPv6 packet processing failed", e)
                }
            }
            is IpParser.Result.Icmpv4 -> {
                try {
                    if (!Icmpv4Handler.handle(result.packet, result.header, tunWriter)) {
                        DiagnosticLogger.logServiceEvent(
                            "ICMPV4 EXTERNAL_UNFORWARDED type=${result.type} code=${result.code} " +
                                "dst=${result.header.destinationAddress.hostAddress}"
                        )
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "ICMPv4 packet processing failed", e)
                }
            }
            is IpParser.Result.Ipv6 -> {
                when (result.header.nextHeader) {
                    IPv6Header.PROTOCOL_TCP -> ipv6TcpEngine.submitTunPacket(result.packet, result.header)
                    IPv6Header.PROTOCOL_UDP -> ipv6UdpEngine.submitTunPacket(result.packet, result.header)
                }
            }
            is IpParser.Result.Ipv4 -> {
                if (result.header.isFragmented) {
                    val count = IpParser.fragmentedIpv4Count.incrementAndGet()
                    if (count == 1L || count % 50L == 0L) {
                        DiagnosticLogger.logServiceEvent("IPV4 FRAGMENT UNSUPPORTED total_seen=$count")
                    }
                    return
                }

                when (result.header.protocol) {
                    IPv4Header.PROTOCOL_TCP -> tcpEngine.submitTunPacket(packet, result.header)
                    IPv4Header.PROTOCOL_UDP -> udpEngine.submitTunPacket(packet, result.header)
                }
            }
        }
    }

    /**
     * Supply DNS addresses to Android's VPN LinkProperties.
     * Android 7 WebView/Chromium may require a non-empty VPN DNS list even when
     * TCP/UDP forwarding itself is working. Prefer the active physical network's
     * DNS configuration and keep only a small deterministic fallback list.
     */
    private fun discoverPhysicalDnsServers(): List<String> {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val candidates = mutableListOf<Pair<Int, List<String>>>()
        for (network in cm.allNetworks) {
            val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP &&
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            val lp = runCatching { cm.getLinkProperties(network) }.getOrNull() ?: continue
            val dns = lp.dnsServers
                .mapNotNull { addr ->
                    val host = addr.hostAddress?.substringBefore('%') ?: return@mapNotNull null
                    // Link-local (fe80::1%wlan0) and loopback resolvers are only valid on the
                    // physical interface; publishing them on tun0 would just break resolution.
                    if (host.isBlank() || addr.isAnyLocalAddress || addr.isLinkLocalAddress ||
                        addr.isLoopbackAddress || addr.isMulticastAddress) null else host
                }
                .distinct()
            if (dns.isEmpty()) continue
            val rank = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 300
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 250
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 200
                else -> 0
            }
            candidates += rank to dns
        }

        val physical = candidates
            .sortedByDescending { it.first }
            .firstOrNull()?.second.orEmpty()

        // IPv4 first on Android 7/legacy WebView, then globally routable IPv6.
        val ordered = physical.sortedWith(compareBy<String> { it.contains(":") }.thenBy { it })
            .take(2)
        if (ordered.isNotEmpty()) return ordered

        return listOf("1.1.1.1", "8.8.8.8")
    }

    private fun updateVpnUnderlyingNetwork() {
        if (!running.get() || !::networkMonitor.isInitialized) return
        val network = networkMonitor.currentUnderlyingNetwork() ?: return
        runCatching {
            setUnderlyingNetworks(arrayOf(network))
            DiagnosticLogger.logServiceEvent("VPN UNDERLYING NETWORK updated=$network")
        }.onFailure {
            DiagnosticLogger.logServiceEvent("VPN UNDERLYING NETWORK update_failed=${it.javaClass.simpleName}")
        }
    }

    private fun stopVpn(stopService: Boolean = true) {
        if (!running.compareAndSet(true, false)) {
            isRunning = false
            return
        }
        isRunning = false
        if (::ruleEngine.isInitialized) ruleEngine.setConfiguredVpnDnsServers(emptySet())
        configuredDnsServers = emptyList()

        if (::networkMonitor.isInitialized) {
            try { networkMonitor.stop() } catch (_: Exception) { }
        }

        // Unblock the blocking TUN read before joining the reader.
        try { tunInputPfd?.close() } catch (_: Exception) { }
        tunInputPfd = null

        if (::tcpEngine.isInitialized) {
            tcpEngine.stop()
            activeTcpSessions = tcpEngine.activeSessions()
        }
        if (::udpEngine.isInitialized) {
            udpEngine.stop()
            activeUdpSessions = udpEngine.activeSessions()
        }
        if (::ipv6TcpEngine.isInitialized) ipv6TcpEngine.stop()
        if (::ipv6UdpEngine.isInitialized) ipv6UdpEngine.stop()
        if (::uidResolver.isInitialized) uidResolver.clear()

        try { tunOutputPfd?.close() } catch (_: Exception) { }
        tunOutputPfd = null
        IpParser.ipv6FragmentReassembler.clear()
        try { vpnInterface?.close() } catch (_: Exception) { }
        vpnInterface = null

        try { tunReaderThread?.join(1000) } catch (_: Exception) { }
        tunReaderThread = null

        currentNetworkKind = NetworkKind.NONE
        currentRoaming = false
        activeTcpSessions = 0
        activeUdpSessions = 0
        DiagnosticLogger.logServiceEvent("VPN ${com.hydra.firewall.BuildConfig.BUILD_LABEL} DETENIDA")
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) { }
        if (stopService) stopSelf()
    }

    override fun onDestroy() {
        NotificationHelper.stopLiveStatus()
        policyHandler.removeCallbacks(scheduleRefreshRunnable)
        lifecycleWatcher?.unregister()
        lifecycleWatcher = null
        stopVpn()
        val unexpected = ServiceTamperMonitor.checkOnDestroy()
        if (unexpected) {
            NotificationHelper.notifyTamper(this)
            if (servicePrefs.getBoolean(KEY_DESIRED_RUNNING, false)) {
                VpnRecoveryScheduler.schedule(this)
            }
        } else {
            VpnRecoveryScheduler.cancel(this)
        }
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (servicePrefs.getBoolean(KEY_DESIRED_RUNNING, false)) {
            VpnRecoveryScheduler.schedule(this, 3_000L)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onRevoke() {
        setDesiredRunning(false)
        VpnRecoveryScheduler.cancel(this)
        ServiceTamperMonitor.markIntentionalStop()
        NotificationHelper.stopLiveStatus()
        policyHandler.removeCallbacks(scheduleRefreshRunnable)
        stopVpn()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Hydra Firewall",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = com.hydra.firewall.BuildConfig.BUILD_LABEL
                setShowBadge(false)
            }
        )
    }

    private fun startForegroundWithNotification() {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Hydra Firewall")
            .setContentText("${com.hydra.firewall.BuildConfig.VERSION_NAME} activo")
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        val liveNotification = NotificationHelper.buildForegroundNotification(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                liveNotification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, liveNotification)
        }
        NotificationHelper.startLiveStatus(this)
    }
}
