package com.hydra.firewall.vpn

import android.content.Context
import android.os.PowerManager
import android.os.Process
import com.hydra.firewall.security.SecurityEventStore
import com.hydra.firewall.security.ThreatSignatureStore
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Calendar
import java.util.concurrent.ConcurrentHashMap

class RuleEngine(private val store: RuleStore, context: Context) {
    enum class Decision { ALLOW, BLOCK, PROMPT }

    private val appContext = context.applicationContext
    private val powerManager = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
    private var roaming = false
    private var currentNetwork = NetworkKind.NONE
    private val ipBlockStore = IpBlockStore(appContext)
    private val advancedRuleStore = AdvancedRuleStore(appContext)
    private val essentialAppsStore = EssentialAppsStore(appContext)
    private val trustedAppsStore = TrustedAppsStore(appContext)
    private val customProtectionStore = CustomProtectionProfileStore(appContext)
    private val promptSuppressionLogged = ConcurrentHashMap.newKeySet<Int>()

    @Volatile
    private var configuredVpnDnsServers: Set<String> = emptySet()

    fun setConfiguredVpnDnsServers(servers: Collection<String>) {
        configuredVpnDnsServers = servers
            .map { it.substringBefore('%').trim() }
            .filter { it.isNotEmpty() }
            .toSet()
    }

    fun getRule(uid: Int): RuleStore.Rule = store.getRule(uid)
    fun getSchedule(uid: Int): RuleStore.Schedule = store.getSchedule(uid)
    fun setSchedule(uid: Int, schedule: RuleStore.Schedule) = store.setSchedule(uid, schedule)
    fun setNetworkState(kind: NetworkKind, isRoaming: Boolean) { currentNetwork = kind; roaming = isRoaming }
    fun isRoaming(): Boolean = roaming
    fun isSecureDnsEnabled(): Boolean = store.secureDnsEnabled

    fun isProtectedCompatibility(uid: Int, packageName: String? = null): Boolean {
        if (uid == Process.INVALID_UID && packageName.isNullOrBlank()) return false
        if (AppCompatibilityPolicyStore.isProtectedCompatibility(packageName)) return true
        if (uid != Process.INVALID_UID) {
            val packages = runCatching { appContext.packageManager.getPackagesForUid(uid) }.getOrNull().orEmpty()
            if (packages.any { AppCompatibilityPolicyStore.isProtectedCompatibility(it) }) return true
        }
        return false
    }

    /** True only for the opt-in diagnostic mode that relaxes optional domain/QUIC filtering. */
    fun isCompatibilityDiagnostic(uid: Int, packageName: String? = null): Boolean {
        if (AppCompatibilityPolicyStore.getMode(packageName) == AppCompatibilityMode.ESSENTIAL_COMPAT) return true
        if (uid != Process.INVALID_UID) {
            val packages = runCatching { appContext.packageManager.getPackagesForUid(uid) }.getOrNull().orEmpty()
            if (packages.any { AppCompatibilityPolicyStore.getMode(it) == AppCompatibilityMode.ESSENTIAL_COMPAT }) return true
        }
        return false
    }

    fun shouldBypassOptionalDomainFilter(uid: Int, packageName: String? = null): Boolean =
        (customProtectionForUid(uid, packageName)?.adTrackerBlocklist == false) ||
            isCompatibilityDiagnostic(uid, packageName) ||
            isFullConnectivityAllowed(uid, currentNetwork) ||
            isUserEssential(uid)

    /** User-selected Essential mode is stronger than the normal per-app policy.
     * It keeps the app inside HYDRA but bypasses normal app-level filters so the
     * app can maintain full connectivity. Critical security controls and the
     * global kill-switch remain authoritative.
     */
    fun isUserEssential(uid: Int): Boolean {
        if (uid == Process.INVALID_UID) return false
        if (essentialAppsStore.isUserEssential(uid)) return true
        val packages = runCatching { appContext.packageManager.getPackagesForUid(uid) }.getOrNull().orEmpty()
        return packages.any { pkg ->
            val mode = AppCompatibilityPolicyStore.getMode(pkg)
            mode == AppCompatibilityMode.ESSENTIAL || mode == AppCompatibilityMode.ESSENTIAL_COMPAT
        }
    }

    /**
     * Fully allowed apps keep the firewall/Threat-Intel layer, but optional
     * compatibility filters must not break their connectivity. This includes
     * Hydra Secure DNS interception, normal ad/tracker blocklists and optional
     * TLS fingerprint blocking.
     */
    fun shouldBypassSecureDns(uid: Int, packageName: String?): Boolean =
        (customProtectionForUid(uid, packageName)?.secureDns == false) ||
            isFullConnectivityAllowed(uid, currentNetwork) ||
            isProtectedCompatibility(uid, packageName)

    fun shouldBypassOptionalTlsFilter(uid: Int, packageName: String?, network: NetworkKind = currentNetwork): Boolean =
        (customProtectionForUid(uid, packageName)?.tlsFingerprint == false) ||
            isFullConnectivityAllowed(uid, network) ||
            isProtectedCompatibility(uid, packageName)

    fun isCustomProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName) != null

    fun isTlsSniProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.tlsSniFilter ?: true

    fun isQuicProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.quicProtection ?: true

    fun isTlsFingerprintProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.tlsFingerprint ?: true

    fun isThreatProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.threatProtection ?: true

    fun shouldBlockLocalNetwork(uid: Int, packageName: String? = null, destination: InetAddress? = null): Boolean {
        if (destination == null || !isLocalNetwork(destination)) return false
        val custom = customProtectionForUid(uid, packageName)
        return custom?.blockLocalNetwork ?: (!store.allowLocalNetwork && !isUserEssential(uid))
    }

    private fun customProtectionForUid(uid: Int, packageName: String? = null): CustomProtectionProfileStore.Profile? {
        if (uid == Process.INVALID_UID) return null
        val direct = packageName?.takeIf { it.isNotBlank() }
        if (direct != null && AppCompatibilityPolicyStore.getMode(direct) == AppCompatibilityMode.CUSTOM) {
            return customProtectionStore.get(uid)
        }
        val packages = runCatching { appContext.packageManager.getPackagesForUid(uid) }.getOrNull().orEmpty()
        if (packages.any { AppCompatibilityPolicyStore.getMode(it) == AppCompatibilityMode.CUSTOM }) {
            return customProtectionStore.get(uid)
        }
        return null
    }

    /**
     * Evaluate only the app-level policy (permission/prompt/rules), without
     * checking the concrete destination IP. DNS filtering must use this before
     * consulting the normal ad/tracker blocklist, otherwise the first DNS query
     * to a blocked ad/tracker domain can be swallowed without ever asking the
     * user for the app-level decision.
     */
    fun evaluateApplicationPolicy(
        uid: Int,
        network: NetworkKind,
        protocol: String? = null,
        port: Int? = null,
        destination: InetAddress? = null
    ): Decision {
        precheck(uid, store.globalBlockAll, store.invalidUidAllowed, essentialAppsStore.isEssential(uid))?.let {
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=${it.name} reason=${if (uid == Process.INVALID_UID) "INVALID_UID" else if (store.globalBlockAll) "GLOBAL_BLOCK_ALL" else "PRECHECK"}"
            )
            return it
        }
        if (destination != null) {
            val host = destination.hostAddress?.substringBefore('%').orEmpty()
            if (host.isNotBlank() && ipBlockStore.isAllowedForUid(uid, host)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=USER_IP_EXCEPTION destination=$host network=${network.displayName}"
                )
                return Decision.ALLOW
            }
            // Android 7/legacy DNS resolution may emit the resolver query from
            // the system/netd UID (commonly UID 0). Such traffic must be allowed
            // to the active local/network resolver by default; otherwise the
            // app's first DNS lookup can be dropped before the app-level prompt
            // is even reachable. Keep global IP blocks and confirmed threats
            // authoritative: this exception only applies after the checks above.
            if (shouldAllowSystemDns(uid, port ?: -1, destination)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=SYSTEM_DNS_DEFAULT destination=$host port=${port ?: -1} network=${network.displayName}"
                )
                return Decision.ALLOW
            }
        }
        return evaluateApplicationPolicyAfterPrecheck(uid, network, protocol, port)
    }

    fun evaluate(uid: Int, network: NetworkKind, destination: InetAddress? = null, protocol: String? = null, port: Int? = null): Decision {
        // Security prechecks must run in the fail-closed order below.
        // In particular, GLOBAL BLOCK ALL must take precedence over the
        // optional "allow unknown UID" policy. Otherwise an unresolved UID
        // could become an unintended exception to the kill-switch.
        precheck(uid, store.globalBlockAll, store.invalidUidAllowed, essentialAppsStore.isEssential(uid))?.let {
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=${it.name} reason=${if (uid == Process.INVALID_UID) "INVALID_UID" else if (store.globalBlockAll) "GLOBAL_BLOCK_ALL" else "PRECHECK"}"
            )
            return it
        }
        if (isScheduleBlocked(uid)) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCHEDULE")
            return Decision.BLOCK
        }

        // FIRST-CONNECTION PROMPT MUST HAPPEN BEFORE DESTINATION-LEVEL OPTIONAL
        // FILTERS. Otherwise a new app can hit a public IP/local-network block
        // or another destination precheck and be silently denied without ever
        // reaching the user decision UI. Confirmed security controls are still
        // enforced after the user has an explicit app policy; this early prompt
        // is only for a real application UID with no saved rule, not essential,
        // and not auto-trusted.
        if (shouldPromptFirstConnection(uid)) {
            val pkg = packageNameForUid(uid)
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=PROMPT reason=FIRST_CONNECTION_EARLY network=${network.displayName} pkg=${pkg ?: "unknown"}"
            )
            return Decision.PROMPT
        }

        if (destination != null) {
            val host = destination.hostAddress?.substringBefore('%') ?: ""
            if (ipBlockStore.isBlocked(host)) {
                                return Decision.BLOCK
            }
            val packageName = packageNameForUid(uid)
            val threatMatch = if (isThreatProtectionEnabled(uid, packageName)) {
                ThreatSignatureStore.matchIp(appContext, host)
            } else null
            if (threatMatch != null) {
                ThreatSignatureStore.recordNetworkBlock(appContext)
                SecurityEventStore.record(
                    appContext,
                    "THREAT_NETWORK_BLOCK",
                    "Threat blocked: ${threatMatch.match.name}",
                    "IP ${threatMatch.normalized} • ${threatMatch.match.family ?: "network threat"}",
                    threatMatch.match.severity
                )
                NotificationHelper.notifyThreatBlocked(
                    appContext, packageName, threatMatch.normalized,
                    threatMatch.match.family, threatMatch.match.severity
                )
                                return Decision.BLOCK
            }
            // Explicit user IP exceptions are checked after confirmed threat
            // matches so an accidental tap cannot override Hydra threat intel.
            // They are scoped to the UID, not global, and intentionally work for
            // local/system DNS endpoints such as 192.168.1.1:53.
            if (host.isNotBlank() && ipBlockStore.isAllowedForUid(uid, host)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=USER_IP_EXCEPTION destination=$host network=${network.displayName}"
                )
                return Decision.ALLOW
            }
            // System/netd DNS to the active/local resolver is a transport
            // prerequisite for normal Android applications. Allow it by default
            // for system/root UIDs, while leaving the global IP block, confirmed
            // threat matches and explicit user IP blocks authoritative.
            if (shouldAllowSystemDns(uid, port ?: -1, destination)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=SYSTEM_DNS_DEFAULT destination=$host port=${port ?: -1} network=${network.displayName}"
                )
                // Domain filtering still happens in the DNS layer.
                return Decision.ALLOW
            }
            if (shouldBlockLocalNetwork(uid, packageName, destination)) {
                                return Decision.BLOCK
            }
        }
        return evaluateApplicationPolicyAfterPrecheck(uid, network, protocol, port, checkSchedule = false)
    }

    /** Shared app-policy core used both by normal packet evaluation and by the
     * DNS prefilter. It deliberately has no destination/IP checks. */
    private fun evaluateApplicationPolicyAfterPrecheck(
        uid: Int,
        network: NetworkKind,
        protocol: String? = null,
        port: Int? = null,
        checkSchedule: Boolean = true
    ): Decision {
        if (checkSchedule && isScheduleBlocked(uid)) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCHEDULE")
            return Decision.BLOCK
        }
        // The optional live self-test intentionally includes HYDRA itself in
        // the VPN. Permit only HYDRA's own UID during that short-lived mode so
        // the test does not get stuck waiting for its own first-connection UI.
        if (FirewallVpnService.liveTestMode && uid == Process.myUid()) {
            return Decision.ALLOW
        }
        // Essential mode keeps the app inside HYDRA while allowing normal network
        // connectivity when no explicit Wi-Fi/Mobile rule exists. Explicit user
        // blocks, schedules, advanced rules and confirmed security controls remain
        // authoritative.
        if (!isUserEssential(uid) && store.blockWhenScreenOff && !isScreenInteractive()) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCREEN_OFF")
            return Decision.BLOCK
        }
        if (!isUserEssential(uid) && store.blockWhenRoaming && roaming && network == NetworkKind.MOBILE) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=ROAMING")
            return Decision.BLOCK
        }
        // Ordinary applications do not bypass the first-connection prompt.
        // Optional trusted-source auto-allow is explicitly controlled by the
        // user-facing "Apps de confianza" switch and is OFF by default.
        if (!store.hasExplicitRule(uid) && trustedAppsStore.isAutoTrusted(uid)) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=ALLOW reason=TRUSTED_APP network=${network.displayName} pkg=${packageNameForUid(uid) ?: "unknown"}")
            return Decision.ALLOW
        }
        val temporary = store.getTemporaryRule(uid)
        if (temporary != null) {
            return when (network) {
                NetworkKind.WIFI -> if (temporary.wifiAllowed) Decision.ALLOW else Decision.BLOCK
                NetworkKind.MOBILE -> if (temporary.mobileAllowed) Decision.ALLOW else Decision.BLOCK
                NetworkKind.OTHER -> if (temporary.wifiAllowed || temporary.mobileAllowed) Decision.ALLOW else Decision.BLOCK
                NetworkKind.NONE -> Decision.BLOCK
            }
        }
        if (protocol != null && port != null) {
            advancedRuleStore.evaluate(uid, protocol, port)?.let { matched ->
                val decision = if (matched) Decision.ALLOW else Decision.BLOCK
                DiagnosticLogger.logServiceEvent("ADVANCED_RULE_MATCH uid=$uid proto=${protocol.uppercase()} port=$port decision=$decision")
                return decision
            }
        }
        if (isUserEssential(uid) && !store.hasExplicitRule(uid)) {
            val decision = when (network) {
                NetworkKind.WIFI, NetworkKind.MOBILE, NetworkKind.OTHER -> Decision.ALLOW
                NetworkKind.NONE -> Decision.BLOCK
            }
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=${decision.name} reason=USER_ESSENTIAL_DEFAULT network=${network.displayName} pkg=${packageNameForUid(uid) ?: "unknown"}"
            )
            return decision
        }
        if (store.askOnFirstConnection && !store.hasExplicitRule(uid)) {
            // Only real application UIDs can receive the first-connection prompt.
            // UID 0 and Android system/root UIDs have no user-facing package rule
            // to configure and appeared in FIX123 as "Aplicación desconocida"
            // (notably for DNS traffic to the physical resolver). Fail closed
            // instead of prompting the user for a non-app identity.
            val promptPackage = packageNameForUid(uid)
            if (uid < Process.FIRST_APPLICATION_UID || promptPackage.isNullOrBlank()) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=BLOCK reason=NON_APPLICATION_UID network=${network.displayName} pkg=${promptPackage ?: "unknown"}"
                )
                return Decision.BLOCK
            }
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=PROMPT reason=NO_EXPLICIT_RULE network=${network.displayName} pkg=$promptPackage")
            return Decision.PROMPT
        }
        val rule = store.getRule(uid)
        val decision = when (network) {
            NetworkKind.WIFI -> if (rule.wifiAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.MOBILE -> if (rule.mobileAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.OTHER -> if (rule.wifiAllowed || rule.mobileAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.NONE -> Decision.BLOCK
        }
        DiagnosticLogger.logServiceEvent(
            "APP_POLICY_DECISION uid=$uid decision=${decision.name} reason=${if (store.hasExplicitRule(uid)) "EXPLICIT_RULE" else "DEFAULT_RULE"} network=${network.displayName} wifi=${rule.wifiAllowed} mobile=${rule.mobileAllowed} pkg=${packageNameForUid(uid) ?: "unknown"}"
        )
        return decision
    }

    fun isAllowed(uid: Int, network: NetworkKind, destination: InetAddress? = null, protocol: String? = null, port: Int? = null): Boolean =
        evaluate(uid, network, destination, protocol, port) == Decision.ALLOW

    /**
     * True when the UID has an effective app-level allow for this network.
     * This is intentionally narrower than RuleEngine.evaluate(): global
     * lockdown, schedules, explicit advanced blocks and confirmed security
     * indicators still remain authoritative.
     */
    private fun shouldPromptFirstConnection(uid: Int): Boolean {
        if (uid < Process.FIRST_APPLICATION_UID || uid == Process.INVALID_UID) return false
        if (!store.askOnFirstConnection) {
            logPromptSuppressionOnce(uid, "ASK_FIRST_DISABLED")
            return false
        }
        if (store.hasExplicitRule(uid)) {
            logPromptSuppressionOnce(uid, "EXPLICIT_RULE")
            return false
        }
        if (isUserEssential(uid)) {
            logPromptSuppressionOnce(uid, "ESSENTIAL")
            return false
        }
        if (trustedAppsStore.isAutoTrusted(uid)) {
            logPromptSuppressionOnce(uid, "TRUSTED_APP")
            return false
        }
        val pkg = packageNameForUid(uid)
        if (pkg.isNullOrBlank()) {
            logPromptSuppressionOnce(uid, "PACKAGE_NOT_FOUND")
            return false
        }
        return true
    }

    private fun logPromptSuppressionOnce(uid: Int, reason: String) {
        if (promptSuppressionLogged.add(uid)) {
            DiagnosticLogger.logServiceEvent(
                "PROMPT_SUPPRESSED uid=$uid reason=$reason pkg=${packageNameForUid(uid) ?: "unknown"}"
            )
        }
    }

    fun isFullConnectivityAllowed(uid: Int, network: NetworkKind): Boolean {
        if (uid == Process.INVALID_UID) return false
        if (store.globalBlockAll) return false
        if (isScheduleBlocked(uid)) return false
        if (isUserEssential(uid) && !store.hasExplicitRule(uid)) {
            return network != NetworkKind.NONE
        }
        if (trustedAppsStore.isAutoTrusted(uid) && !store.hasExplicitRule(uid)) return true

        val temporary = store.getTemporaryRule(uid)
        if (temporary != null) {
            return when (network) {
                NetworkKind.WIFI -> temporary.wifiAllowed
                NetworkKind.MOBILE -> temporary.mobileAllowed
                NetworkKind.OTHER -> temporary.wifiAllowed || temporary.mobileAllowed
                NetworkKind.NONE -> false
            }
        }
        if (!store.hasExplicitRule(uid)) return false
        val rule = store.getRule(uid)
        return when (network) {
            NetworkKind.WIFI -> rule.wifiAllowed
            NetworkKind.MOBILE -> rule.mobileAllowed
            NetworkKind.OTHER -> rule.wifiAllowed || rule.mobileAllowed
            NetworkKind.NONE -> false
        }
    }

    private fun shouldAllowSystemDns(uid: Int, port: Int, destination: InetAddress?): Boolean {
        if (port != 53) return false
        if (uid !in 0 until Process.FIRST_APPLICATION_UID) return false
        val host = destination?.hostAddress?.substringBefore('%')?.trim().orEmpty()
        if (host.isEmpty()) return false
        if (configuredVpnDnsServers.contains(host)) return true

        // Fallback for Android/netd when LinkProperties and VPN DNS publication
        // do not expose the physical resolver early enough during VPN startup.
        // Common home/router resolvers are RFC1918 IPv4; IPv6 DNS on a LAN is
        // commonly link-local (for example fe80::1). This is intentionally
        // limited to system UIDs and DNS port 53.
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
        return when {
            address is Inet4Address -> {
                val bytes = address.address
                val a = bytes[0].toInt() and 0xFF
                val b = bytes[1].toInt() and 0xFF
                (a == 10) ||
                    (a == 172 && b in 16..31) ||
                    (a == 192 && b == 168)
            }
            address is Inet6Address -> address.isLinkLocalAddress
            else -> false
        }
    }


    fun isScheduleBlocked(uid: Int, nowMillis: Long = System.currentTimeMillis()): Boolean {
        val s = store.getSchedule(uid)
        if (!s.enabled || s.daysMask == 0) return false
        val cal = Calendar.getInstance().apply { timeInMillis = nowMillis }
        val dow = cal.get(Calendar.DAY_OF_WEEK)
        val currentDay = when (dow) {
            Calendar.MONDAY -> 0
            Calendar.TUESDAY -> 1
            Calendar.WEDNESDAY -> 2
            Calendar.THURSDAY -> 3
            Calendar.FRIDAY -> 4
            Calendar.SATURDAY -> 5
            else -> 6
        }
        val minute = cal.get(Calendar.HOUR_OF_DAY) * 60 + cal.get(Calendar.MINUTE)
        if (s.startMinutes == s.endMinutes) return (s.daysMask and (1 shl currentDay)) != 0
        if (s.startMinutes < s.endMinutes) {
            return (s.daysMask and (1 shl currentDay)) != 0 && minute >= s.startMinutes && minute < s.endMinutes
        }
        if (minute >= s.startMinutes) {
            return (s.daysMask and (1 shl currentDay)) != 0
        }
        val previousDay = (currentDay + 6) % 7
        return (s.daysMask and (1 shl previousDay)) != 0 && minute < s.endMinutes
    }


    private fun packageNameForUid(uid: Int): String? = runCatching {
        appContext.packageManager.getPackagesForUid(uid)?.firstOrNull()
    }.getOrNull()


    companion object {
        /**
         * Security-critical ordering shared by runtime policy evaluation and
         * regression tests. Global Block All is always evaluated before the
         * optional invalid-UID allowance. An unresolved UID is never treated
         * as essential.
         */
        internal fun precheck(
            uid: Int,
            globalBlockAll: Boolean,
            invalidUidAllowed: Boolean,
            essential: Boolean
        ): Decision? {
            if (globalBlockAll) return Decision.BLOCK
            if (uid == Process.INVALID_UID) {
                return if (invalidUidAllowed) Decision.ALLOW else Decision.BLOCK
            }
            return null
        }

        @JvmStatic
        fun shouldAllowSystemDns(
            uid: Int,
            port: Int,
            destinationHost: String?,
            configuredDnsServers: Set<String>
        ): Boolean {
            if (port != 53) return false
            if (uid !in 0 until Process.FIRST_APPLICATION_UID) return false
            val host = destinationHost?.substringBefore('%')?.trim().orEmpty()
            if (host.isEmpty()) return false
            if (configuredDnsServers.contains(host)) return true
            val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
            return when {
                address is Inet4Address -> {
                    val bytes = address.address
                    val a = bytes[0].toInt() and 0xFF
                    val b = bytes[1].toInt() and 0xFF
                    (a == 10) || (a == 172 && b in 16..31) || (a == 192 && b == 168)
                }
                address is Inet6Address -> address.isLinkLocalAddress
                else -> false
            }
        }
    }

    private fun isScreenInteractive(): Boolean = if (android.os.Build.VERSION.SDK_INT >= 20) powerManager.isInteractive else true

    private fun isLocalNetwork(address: InetAddress): Boolean {
        if (address is Inet4Address) {
            val bytes = address.address
            val a = bytes[0].toInt() and 0xFF
            val b = bytes[1].toInt() and 0xFF
            return a == 10 ||
                (a == 172 && b in 16..31) ||
                (a == 192 && b == 168) ||
                (a == 169 && b == 254) ||
                a == 127
        }

        if (address is Inet6Address) {
            if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) return true
            val bytes = address.address
            if (bytes.isNotEmpty() && (bytes[0].toInt() and 0xFE) == 0xFC) return true
        }

        return false
    }

}