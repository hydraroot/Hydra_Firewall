package com.hydra.firewall.vpn

import android.content.Context
import android.os.Process
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Recovers the first-connection prompt when Android 7 exposes a TUN flow before
 * the corresponding socket appears in /proc/net. The original packet remains
 * fail-closed; this class only retries attribution in the background and opens a
 * prompt once a real application UID is found.
 */
object UnresolvedUidPromptRecovery {
    private const val MAX_PENDING = 128
    private val executor: ScheduledExecutorService = Executors.newScheduledThreadPool(1) { r ->
        Thread(r, "Hydra-UidPromptRecovery").apply { isDaemon = true }
    }
    private val pending = ConcurrentHashMap<SessionKey, Boolean>()

    fun schedule(
        context: Context,
        key: SessionKey,
        network: NetworkKind,
        resolver: UidResolver
    ) {
        if (key.srcPort <= 0 || key.dstPort <= 0 || pending.containsKey(key)) return
        if (pending.size >= MAX_PENDING) {
            DiagnosticLogger.logServiceEvent(
                "UID_RECOVERY_RATE_LIMIT pending=${pending.size} src=${key.srcAddr.hostAddress}:${key.srcPort} dst=${key.dstAddr.hostAddress}:${key.dstPort}"
            )
            return
        }
        if (pending.putIfAbsent(key, true) != null) return

        val appContext = context.applicationContext
        DiagnosticLogger.logServiceEvent(
            "UID_RECOVERY_SCHEDULED protocol=${key.protocol} network=${network.displayName} src=${key.srcAddr.hostAddress}:${key.srcPort} dst=${key.dstAddr.hostAddress}:${key.dstPort}"
        )
        val delays = longArrayOf(75L, 150L, 250L, 400L, 650L, 1000L, 1500L, 2000L)
        executor.execute {
            try {
                var resolvedUid = Process.INVALID_UID
                var packageName: String? = null
                for ((index, delayMs) in delays.withIndex()) {
                    if (delayMs > 0L) {
                        try {
                            Thread.sleep(delayMs)
                        } catch (_: InterruptedException) {
                            Thread.currentThread().interrupt()
                            return@execute
                        }
                    }
                    val resolution = resolver.resolve(key, network)
                    if (resolution.uid != Process.INVALID_UID) {
                        resolvedUid = resolution.uid
                        packageName = resolution.packageName
                        DiagnosticLogger.logServiceEvent(
                            "UID_RECOVERY_RESOLVED uid=$resolvedUid pkg=${packageName ?: "unknown"} attempt=${index + 1} via=${resolution.resolvedVia}"
                        )
                        break
                    }
                }

                if (resolvedUid == Process.INVALID_UID) {
                    DiagnosticLogger.logServiceEvent(
                        "UID_RECOVERY_EXPIRED protocol=${key.protocol} src=${key.srcAddr.hostAddress}:${key.srcPort} dst=${key.dstAddr.hostAddress}:${key.dstPort}"
                    )
                    return@execute
                }

                val engine = RuleEngine(RuleStore(appContext), appContext)
                when (engine.evaluate(resolvedUid, network, key.dstAddr, protocolFor(key), key.dstPort)) {
                    RuleEngine.Decision.PROMPT -> {
                        val rule = engine.getRule(resolvedUid)
                        val queued = DecisionRequestManager.request(
                            context = appContext,
                            key = key,
                            uid = resolvedUid,
                            packageName = packageName,
                            network = network,
                            protocolLabel = protocolForLabel(key),
                            initialWifiAllowed = rule.wifiAllowed,
                            initialMobileAllowed = rule.mobileAllowed
                        ) { wifiAllowed, mobileAllowed ->
                            RuleStore(appContext).apply {
                                setWifiAllowed(resolvedUid, wifiAllowed)
                                setMobileAllowed(resolvedUid, mobileAllowed)
                            }
                            DiagnosticLogger.logServiceEvent(
                                "ACCESS_DECISION_APPLIED uid=$resolvedUid pkg=${packageName ?: "unknown"} recovery_pending=discarded_wait_for_fresh_connection"
                            )
                        }
                        DiagnosticLogger.logServiceEvent(
                            "UID_RECOVERY_PROMPT uid=$resolvedUid pkg=${packageName ?: "unknown"} queued=$queued network=${network.displayName}"
                        )
                    }
                    RuleEngine.Decision.ALLOW -> DiagnosticLogger.logServiceEvent(
                        "UID_RECOVERY_NOT_NEEDED uid=$resolvedUid pkg=${packageName ?: "unknown"} decision=ALLOW"
                    )
                    RuleEngine.Decision.BLOCK -> DiagnosticLogger.logServiceEvent(
                        "UID_RECOVERY_NOT_NEEDED uid=$resolvedUid pkg=${packageName ?: "unknown"} decision=BLOCK"
                    )
                }
            } finally {
                pending.remove(key)
            }
        }
    }

    private fun protocolFor(key: SessionKey): String =
        if (key.protocol == UidResolver.PROTOCOL_UDP) "UDP" else "TCP"

    private fun protocolForLabel(key: SessionKey): String = protocolFor(key)
}
