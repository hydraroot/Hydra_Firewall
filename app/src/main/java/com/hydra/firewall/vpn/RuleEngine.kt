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
    private val customProtectionStore = CustomProtectionProfileStore(appContext)
    private val promptSuppressionLogged = ConcurrentHashMap.newKeySet<Int>()
    // PackageManager.getPackagesForUid() is a Binder call. Cache stable UID ownership
    // for the VPN service lifetime and invalidate on PACKAGE_ADDED/REPLACED/REMOVED.
    private val packagesByUid = ConcurrentHashMap<Int, List<String>>()
    private val maxPackageUidCacheEntries = 1024

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
            val packages = packagesForUid(uid)
            if (packages.any { AppCompatibilityPolicyStore.isProtectedCompatibility(it) }) return true
        }
        return false
    }

    fun shouldBypassOptionalDomainFilter(uid: Int, packageName: String? = null): Boolean =
        (customProtectionForUid(uid, packageName)?.adTrackerBlocklist == false) ||
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
        val packages = packagesForUid(uid)
        return packages.any { pkg ->
            AppCompatibilityPolicyStore.getMode(pkg) == AppCompatibilityMode.ESSENTIAL
        }
    }

    /**
     * Fully allowed apps keep the firewall/Threat-Intel layer, but optional
     * compatibility filters must not break their connectivity. This includes
     * Hydra Secure DNS interception, normal ad/tracker blocklists.
     */
    fun shouldBypassSecureDns(uid: Int, packageName: String?): Boolean =
        (customProtectionForUid(uid, packageName)?.secureDns == false) ||
            isFullConnectivityAllowed(uid, currentNetwork) ||
            isProtectedCompatibility(uid, packageName)

    fun isCustomProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName) != null

    fun isTlsSniProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.tlsSniFilter ?: true

    fun isQuicProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        customProtectionForUid(uid, packageName)?.quicProtection ?: true

    /**
     * Network threat matching is controlled by the single global "Threats + ads"
     * switch. A per-app CUSTOM profile may further disable this layer, but cannot
     * re-enable it after the global master switch has been turned off.
     */
    fun isThreatProtectionEnabled(uid: Int, packageName: String? = null): Boolean =
        store.threatProtectionEnabled && (customProtectionForUid(uid, packageName)?.threatProtection ?: true)

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
        val packages = packagesForUid(uid)
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
    data class Evaluation(
        val decision: Decision,
        /** Stable machine-readable cause captured at decision time for Connection history. */
        val reasonCode: String,
        /** Small factual context (domain, port rule, network, threat name); never a guessed explanation. */
        val reasonDetail: String? = null
    )

    fun evaluateApplicationPolicy(
        uid: Int,
        network: NetworkKind,
        protocol: String? = null,
        port: Int? = null,
        destination: InetAddress? = null
    ): Decision = evaluateApplicationPolicyDetailed(uid, network, protocol, port, destination).decision

    fun evaluateApplicationPolicyDetailed(
        uid: Int,
        network: NetworkKind,
        protocol: String? = null,
        port: Int? = null,
        destination: InetAddress? = null
    ): Evaluation {
        precheckEvaluation(uid)?.let { return it }
        if (destination != null) {
            val host = destination.hostAddress?.substringBefore('%').orEmpty()
            if (host.isNotBlank() && ipBlockStore.isAllowedForUid(uid, host)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=USER_IP_EXCEPTION destination=$host network=${network.displayName}"
                )
                return Evaluation(Decision.ALLOW, "USER_IP_EXCEPTION", host)
            }
            // Android/netd DNS to the active physical resolver is a transport prerequisite.
            if (shouldAllowSystemDns(uid, port ?: -1, destination)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=SYSTEM_DNS_DEFAULT destination=$host port=${port ?: -1} network=${network.displayName}"
                )
                return Evaluation(Decision.ALLOW, "SYSTEM_DNS_DEFAULT", "${host}:${port ?: -1}")
            }
        }
        return evaluateApplicationPolicyAfterPrecheckDetailed(uid, network, protocol, port)
    }

    fun evaluate(
        uid: Int,
        network: NetworkKind,
        destination: InetAddress? = null,
        protocol: String? = null,
        port: Int? = null
    ): Decision = evaluateDetailed(uid, network, destination, protocol, port).decision

    fun evaluateDetailed(
        uid: Int,
        network: NetworkKind,
        destination: InetAddress? = null,
        protocol: String? = null,
        port: Int? = null
    ): Evaluation {
        // Security prechecks run before all optional app rules.
        precheckEvaluation(uid)?.let { return it }

        if (isScheduleBlocked(uid)) {
            val schedule = store.getSchedule(uid)
            val dayNames = listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
                .filterIndexed { index, _ -> (schedule.daysMask and (1 shl index)) != 0 }
            fun clock(minutes: Int): String = "%02d:%02d".format(minutes / 60, minutes % 60)
            val detail = "${dayNames.joinToString(",")}; ${clock(schedule.startMinutes)}-${clock(schedule.endMinutes)}"
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCHEDULE detail=$detail")
            return Evaluation(Decision.BLOCK, "SCHEDULE", detail)
        }

        if (shouldPromptFirstConnection(uid)) {
            val pkg = packageNameForUid(uid)
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=PROMPT reason=FIRST_CONNECTION_EARLY network=${network.displayName} pkg=${pkg ?: "unknown"}"
            )
            return Evaluation(Decision.PROMPT, "FIRST_CONNECTION_PROMPT", network.displayName)
        }

        if (destination != null) {
            val host = destination.hostAddress?.substringBefore('%') ?: ""
            if (ipBlockStore.isBlocked(host)) {
                return Evaluation(Decision.BLOCK, "USER_IP_BLOCK", host)
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
                return Evaluation(
                    Decision.BLOCK,
                    "THREAT_IP",
                    listOf(threatMatch.match.name, threatMatch.match.family, threatMatch.match.source, threatMatch.normalized)
                        .filterNotNull().filter { it.isNotBlank() }.joinToString(" • ")
                )
            }
            if (host.isNotBlank() && ipBlockStore.isAllowedForUid(uid, host)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=USER_IP_EXCEPTION destination=$host network=${network.displayName}"
                )
                return Evaluation(Decision.ALLOW, "USER_IP_EXCEPTION", host)
            }
            if (shouldAllowSystemDns(uid, port ?: -1, destination)) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=ALLOW reason=SYSTEM_DNS_DEFAULT destination=$host port=${port ?: -1} network=${network.displayName}"
                )
                return Evaluation(Decision.ALLOW, "SYSTEM_DNS_DEFAULT", "${host}:${port ?: -1}")
            }
            if (shouldBlockLocalNetwork(uid, packageName, destination)) {
                return Evaluation(Decision.BLOCK, "LOCAL_NETWORK_POLICY", host)
            }
        }
        return evaluateApplicationPolicyAfterPrecheckDetailed(uid, network, protocol, port, checkSchedule = false)
    }

    private fun precheckEvaluation(uid: Int): Evaluation? {
        val decision = precheck(uid, store.globalBlockAll, store.invalidUidAllowed, essentialAppsStore.isEssential(uid))
            ?: return null
        val result = when {
            store.globalBlockAll -> Evaluation(decision, "GLOBAL_BLOCK_ALL")
            uid == Process.INVALID_UID -> Evaluation(decision, "INVALID_UID_POLICY", "uid=$uid")
            else -> Evaluation(decision, "POLICY_PRECHECK")
        }
        DiagnosticLogger.logServiceEvent(
            "APP_POLICY_DECISION uid=$uid decision=${decision.name} reason=${result.reasonCode}"
        )
        return result
    }

    /** Shared app-policy core; returns the exact branch that produced the decision. */
    private fun evaluateApplicationPolicyAfterPrecheckDetailed(
        uid: Int,
        network: NetworkKind,
        protocol: String? = null,
        port: Int? = null,
        checkSchedule: Boolean = true
    ): Evaluation {
        if (checkSchedule && isScheduleBlocked(uid)) {
            val schedule = store.getSchedule(uid)
            val dayNames = listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
                .filterIndexed { index, _ -> (schedule.daysMask and (1 shl index)) != 0 }
            fun clock(minutes: Int): String = "%02d:%02d".format(minutes / 60, minutes % 60)
            val detail = "${dayNames.joinToString(",")}; ${clock(schedule.startMinutes)}-${clock(schedule.endMinutes)}"
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCHEDULE detail=$detail")
            return Evaluation(Decision.BLOCK, "SCHEDULE", detail)
        }
        if (!isUserEssential(uid) && store.blockWhenScreenOff && !isScreenInteractive()) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=SCREEN_OFF")
            return Evaluation(Decision.BLOCK, "SCREEN_OFF")
        }
        if (!isUserEssential(uid) && store.blockWhenRoaming && roaming && network == NetworkKind.MOBILE) {
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=BLOCK reason=ROAMING")
            return Evaluation(Decision.BLOCK, "ROAMING")
        }

        val temporary = store.getTemporaryRule(uid)
        if (temporary != null) {
            val allowed = when (network) {
                NetworkKind.WIFI -> temporary.wifiAllowed
                NetworkKind.MOBILE -> temporary.mobileAllowed
                NetworkKind.OTHER -> temporary.wifiAllowed || temporary.mobileAllowed
                NetworkKind.NONE -> false
            }
            return Evaluation(
                if (allowed) Decision.ALLOW else Decision.BLOCK,
                "TEMPORARY_APP_RULE",
                "${network.displayName}; Wi-Fi=${if (temporary.wifiAllowed) "allow" else "block"}; mobile=${if (temporary.mobileAllowed) "allow" else "block"}"
            )
        }

        if (protocol != null && port != null) {
            val matchedRule = advancedRuleStore.findMatch(uid, protocol, port)
            if (matchedRule != null) {
                val decision = if (matchedRule.allowed) Decision.ALLOW else Decision.BLOCK
                val scope = if (matchedRule.uid == AdvancedRuleStore.GLOBAL_UID) "global" else "app"
                val detail = "${matchedRule.protocol} ${matchedRule.startPort}-${matchedRule.endPort}; scope=$scope; decision=${if (matchedRule.allowed) "allow" else "block"}"
                DiagnosticLogger.logServiceEvent("ADVANCED_RULE_MATCH uid=$uid proto=${protocol.uppercase()} port=$port decision=$decision")
                return Evaluation(decision, "ADVANCED_PORT_RULE", detail)
            }
        }

        if (isUserEssential(uid) && !store.hasExplicitRule(uid)) {
            val decision = when (network) {
                NetworkKind.WIFI, NetworkKind.MOBILE, NetworkKind.OTHER -> Decision.ALLOW
                NetworkKind.NONE -> Decision.BLOCK
            }
            val code = if (decision == Decision.ALLOW) "USER_ESSENTIAL_DEFAULT" else "NO_ACTIVE_NETWORK"
            DiagnosticLogger.logServiceEvent(
                "APP_POLICY_DECISION uid=$uid decision=${decision.name} reason=$code network=${network.displayName} pkg=${packageNameForUid(uid) ?: "unknown"}"
            )
            return Evaluation(decision, code, network.displayName)
        }

        if (store.askOnFirstConnection && !store.hasExplicitRule(uid)) {
            val promptPackage = packageNameForUid(uid)
            if (uid < Process.FIRST_APPLICATION_UID || promptPackage.isNullOrBlank()) {
                DiagnosticLogger.logServiceEvent(
                    "APP_POLICY_DECISION uid=$uid decision=BLOCK reason=NON_APPLICATION_UID network=${network.displayName} pkg=${promptPackage ?: "unknown"}"
                )
                return Evaluation(Decision.BLOCK, "NON_APPLICATION_UID", "uid=$uid")
            }
            DiagnosticLogger.logServiceEvent("APP_POLICY_DECISION uid=$uid decision=PROMPT reason=NO_EXPLICIT_RULE network=${network.displayName} pkg=$promptPackage")
            return Evaluation(Decision.PROMPT, "FIRST_CONNECTION_PROMPT", network.displayName)
        }

        val rule = store.getRule(uid)
        val decision = when (network) {
            NetworkKind.WIFI -> if (rule.wifiAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.MOBILE -> if (rule.mobileAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.OTHER -> if (rule.wifiAllowed || rule.mobileAllowed) Decision.ALLOW else Decision.BLOCK
            NetworkKind.NONE -> Decision.BLOCK
        }
        val code = if (store.hasExplicitRule(uid)) "EXPLICIT_APP_RULE" else "DEFAULT_APP_RULE"
        val detail = "${network.displayName}; Wi-Fi=${if (rule.wifiAllowed) "allow" else "block"}; mobile=${if (rule.mobileAllowed) "allow" else "block"}"
        DiagnosticLogger.logServiceEvent(
            "APP_POLICY_DECISION uid=$uid decision=${decision.name} reason=$code network=${network.displayName} wifi=${rule.wifiAllowed} mobile=${rule.mobileAllowed} pkg=${packageNameForUid(uid) ?: "unknown"}"
        )
        return Evaluation(decision, if (decision == Decision.BLOCK && network == NetworkKind.NONE) "NO_ACTIVE_NETWORK" else code, detail)
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


    private fun packageNameForUid(uid: Int): String? = packagesForUid(uid).firstOrNull()

    private fun packagesForUid(uid: Int): List<String> {
        if (uid == Process.INVALID_UID || uid < 0) return emptyList()
        packagesByUid[uid]?.let { return it }
        val resolved = runCatching {
            appContext.packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        }.getOrDefault(emptyList())
        if (resolved.isEmpty()) return emptyList() // Do not cache transient/unknown results.
        if (packagesByUid.size >= maxPackageUidCacheEntries) packagesByUid.clear()
        return packagesByUid.putIfAbsent(uid, resolved) ?: resolved
    }

    /** Called on package lifecycle broadcasts so shared-UID ownership never stays stale. */
    fun invalidatePackageCache() {
        packagesByUid.clear()
    }


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