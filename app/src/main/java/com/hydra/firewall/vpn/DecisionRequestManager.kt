package com.hydra.firewall.vpn

import android.content.Context
import android.content.Intent
import android.os.Process
import com.hydra.firewall.AppAccessRequestActivity
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Coordinates first-connection access requests between the VPN engines and the
 * user-facing decision Activity. A request waits for the user's per-network
 * decision; the original packet is intentionally not replayed after a long
 * prompt because the app may already have abandoned that flow.
 */
object DecisionRequestManager {
    /** One access screen per app/UID and physical network. TCP/UDP attempts are grouped. */
    data class PromptKey(
        val uid: Int,
        val network: NetworkKind
    )

    data class Attempt(
        val protocolLabel: String,
        val destination: String
    )

    data class Request(
        val token: String,
        val key: SessionKey,
        val promptKey: PromptKey,
        val uid: Int,
        val packageName: String?,
        val network: NetworkKind,
        val protocolLabel: String,
        val initialWifiAllowed: Boolean,
        val initialMobileAllowed: Boolean,
        val onDecision: (Boolean, Boolean) -> Unit
    ) {
        val attempts: java.util.concurrent.CopyOnWriteArrayList<Attempt> = java.util.concurrent.CopyOnWriteArrayList()
        val sessionKeys = java.util.concurrent.CopyOnWriteArraySet<SessionKey>()

        init {
            attempts += Attempt(protocolLabel, formatEndpoint(key.dstAddr, key.dstPort))
            sessionKeys += key
        }

        fun addAttempt(protocol: String, key: SessionKey) {
            val item = Attempt(protocol, formatEndpoint(key.dstAddr, key.dstPort))
            sessionKeys += key
            if (attempts.none { it.protocolLabel == item.protocolLabel && it.destination == item.destination }) {
                attempts += item
                if (attempts.size > 8) attempts.removeAt(0)
            }
        }
    }

    private val byKey = ConcurrentHashMap<SessionKey, Request>()
    private val byToken = ConcurrentHashMap<String, Request>()
    private val byPromptKey = ConcurrentHashMap<PromptKey, Request>()
    private const val MAX_PENDING_PROMPTS = 32
    private const val RELAUNCH_THROTTLE_MS = 1_500L
    private const val PROMPT_WATCHDOG_PERIOD_MS = 2_000L
    private const val PROMPT_WATCHDOG_MAX_MS = 45_000L
    /**
     * After the user answers, the rule is persisted and the VPN may be rebuilt
     * (hundreds of ms to a few seconds). Retransmitted SYNs/UDP packets arriving
     * in that window still evaluate to PROMPT and used to open the same dialog a
     * second time. Remember when each app/network was just resolved and swallow
     * new prompts for a short grace period.
     */
    private const val RESOLVED_GRACE_MS = 6_000L
    private val recentlyResolved = ConcurrentHashMap<PromptKey, Long>()
    private fun markResolved(promptKey: PromptKey) {
        val now = System.currentTimeMillis()
        recentlyResolved[promptKey] = now
        if (recentlyResolved.size > 64) {
            recentlyResolved.entries.removeIf { now - it.value > RESOLVED_GRACE_MS }
        }
    }
    private fun isRecentlyResolved(promptKey: PromptKey): Boolean {
        val at = recentlyResolved[promptKey] ?: return false
        if (System.currentTimeMillis() - at < RESOLVED_GRACE_MS) return true
        recentlyResolved.remove(promptKey)
        return false
    }
    /**
     * Only ONE decision screen is shown at a time. Every other pending request
     * waits in [order] (its notification stays in the tray) and is shown after
     * the current one is answered. Previously every request launched its own
     * Activity and brought itself to front, so with many apps connecting at
     * once the prompts kept replacing each other before the user could answer.
     */
    private val order = java.util.concurrent.ConcurrentLinkedQueue<String>()
    @Volatile private var activeToken: String? = null
    private const val NEXT_PROMPT_DELAY_MS = 450L

    private fun endRequest(token: String) {
        order.remove(token)
        if (activeToken == token) activeToken = null
        scheduleNextPrompt()
    }

    private fun scheduleNextPrompt() {
        promptExecutor.schedule({ launchNextPrompt() }, NEXT_PROMPT_DELAY_MS, TimeUnit.MILLISECONDS)
    }

    private fun launchNextPrompt() {
        val ctx = contextRef ?: return
        synchronized(this) {
            val current = activeToken
            if (current != null && byToken.containsKey(current)) return
            activeToken = null
            val nextToken = order.firstOrNull { byToken.containsKey(it) } ?: return
            val req = byToken[nextToken] ?: return
            launchPromptActivity(ctx, nextToken, req, "QUEUE_NEXT")
        }
    }

    /** Called by the Activity when it is actually on screen (also via notification tap). */
    fun onPromptShown(token: String) {
        if (byToken.containsKey(token)) activeToken = token
    }

    /** Called when the Activity is destroyed without a decision (back / swipe away). */
    fun onPromptClosedWithoutDecision(token: String) {
        synchronized(this) {
            if (!byToken.containsKey(token)) return
            if (activeToken == token) activeToken = null
            // Send it to the back of the queue; do not reopen it right away.
            order.remove(token); order.add(token)
            if (order.any { it != token && byToken.containsKey(it) }) scheduleNextPrompt()
        }
    }

    private val lastPromptLaunchMs = ConcurrentHashMap<String, Long>()
    private val promptWatchdogs = ConcurrentHashMap<String, ScheduledFuture<*>>()
    private val promptExecutor = Executors.newScheduledThreadPool(1) { runnable ->
        Thread(runnable, "Hydra-PromptWatchdog").apply { isDaemon = true }
    }

    // Application context only (never an Activity context) so this can
    // safely outlive the screen that created the request, purely to cancel
    // the fallback notification once the decision is made or cancelled.
    @Volatile private var contextRef: Context? = null

    fun request(
        context: Context,
        key: SessionKey,
        uid: Int,
        packageName: String?,
        network: NetworkKind,
        protocolLabel: String,
        initialWifiAllowed: Boolean,
        initialMobileAllowed: Boolean,
        onDecision: (Boolean, Boolean) -> Unit
    ): Boolean {
        if (uid == Process.INVALID_UID) return false
        // During the controlled self-test HYDRA temporarily includes its own UID
        // inside the VPN. That traffic must never create a user-facing prompt,
        // even if a packet arrives during the restart race before RuleEngine
        // observes liveTestMode.
        if (FirewallVpnService.liveTestMode && uid == Process.myUid()) {
            DiagnosticLogger.logServiceEvent(
                "ACCESS_PROMPT_SUPPRESSED_SELF_TEST_UID uid=$uid pkg=${packageName ?: "unknown"}"
            )
            return false
        }
        // Never create a user prompt for Android/system/root identities.
        // The first-connection UI is only meaningful for real application UIDs.
        if (uid < Process.FIRST_APPLICATION_UID) {
            DiagnosticLogger.logServiceEvent("ACCESS_PROMPT_SUPPRESSED_NON_APP_UID uid=$uid pkg=${packageName ?: "unknown"}")
            return false
        }
        contextRef = context.applicationContext
        synchronized(this) {
            val promptKey = PromptKey(uid, network)

            // One decision screen per app/network. TCP, UDP, IPv4 and IPv6
            // attempts from that same app/network are grouped into the same
            // screen instead of launching a new Activity for every protocol.
            // TCP retransmits commonly reuse the exact same 5-tuple. If the
            // Activity was obscured/lost after the first launch, silently returning
            // here leaves the app blocked forever with no visible prompt. Reuse the
            // existing request and explicitly retry the Activity/notification.
            byKey[key]?.let { existing ->
                existing.addAttempt(protocolLabel, key)
                NotificationHelper.notifyAccessRequest(
                    context = context.applicationContext,
                    token = existing.token,
                    packageName = existing.packageName ?: packageName,
                    uid = existing.uid,
                    network = existing.network,
                    pendingCount = byToken.size,
                    attemptCount = existing.attempts.size
                )
                if (!launchPromptActivity(context.applicationContext, existing.token, existing, protocolLabel)) {
                    schedulePromptWatchdog(context.applicationContext, existing)
                }
                DiagnosticLogger.logServiceEvent(
                    "ACCESS_PROMPT_SAME_FLOW_RELAUNCH uid=$uid pkg=${packageName ?: "unknown"} network=${network.displayName} protocol=$protocolLabel"
                )
                return false
            }
            byPromptKey[promptKey]?.let { existing ->
                existing.addAttempt(protocolLabel, key)
                byKey[key] = existing
                NotificationHelper.notifyAccessRequest(
                    context = context.applicationContext,
                    token = existing.token,
                    packageName = existing.packageName ?: packageName,
                    uid = existing.uid,
                    network = existing.network,
                    pendingCount = byToken.size,
                    attemptCount = existing.attempts.size
                )
                // A previous prompt can still be pending while its Activity was
                // dismissed, lost behind another task, or failed to launch.
                // Do not rely on the notification alone: retry the Activity launch
                // with a small throttle so repeated SYN/UDP packets can restore the
                // visible prompt without stacking dozens of screens.
                if (!launchPromptActivity(context.applicationContext, existing.token, existing, protocolLabel)) {
                    schedulePromptWatchdog(context.applicationContext, existing)
                }
                DiagnosticLogger.logServiceEvent(
                    "ACCESS_PROMPT_GROUPED uid=$uid pkg=${packageName ?: "unknown"} network=${network.displayName} protocol=$protocolLabel attempts=${existing.attempts.size}"
                )
                return false
            }

            if (isRecentlyResolved(promptKey)) {
                DiagnosticLogger.logServiceEvent(
                    "ACCESS_PROMPT_SUPPRESSED_JUST_RESOLVED uid=$uid pkg=${packageName ?: "unknown"} network=${network.displayName} protocol=$protocolLabel"
                )
                return false
            }

            if (byToken.size >= MAX_PENDING_PROMPTS) {
                DiagnosticLogger.logServiceEvent("ACCESS_PROMPT_RATE_LIMIT pending=${byToken.size} uid=$uid pkg=${packageName ?: "unknown"}")
                return false
            }

            val token = UUID.randomUUID().toString()
            val request = Request(
                token, key, promptKey, uid, packageName, network, protocolLabel,
                initialWifiAllowed, initialMobileAllowed, onDecision
            )
            byKey[key] = request
            byToken[token] = request
            byPromptKey[promptKey] = request
            order.add(token)

            // The Activity is the rich decision UI, but a persistent tray
            // notification is also required. On Android 7 the Activity may
            // lose focus or disappear while the network request is still
            // waiting, so the notification is the durable entry point back
            // to the grouped request.
            NotificationHelper.notifyAccessRequest(
                context = context.applicationContext,
                token = token,
                packageName = packageName,
                uid = uid,
                network = network,
                pendingCount = byToken.size,
                attemptCount = request.attempts.size
            )
            // Every distinct app/UID/network request gets its own Activity as well
            // as its own persistent notification. Older builds opened only the first
            // pending request, which made a newly requesting app appear to be silently
            // blocked whenever another app already had a pending prompt.
            if (!launchPromptActivity(context.applicationContext, token, request, protocolLabel)) {
                schedulePromptWatchdog(context.applicationContext, request)
            }
            return true
        }
    }

    fun get(token: String): Request? = byToken[token]

    private fun launchPromptActivity(context: Context, token: String, request: Request, protocolLabel: String): Boolean {
        val active = activeToken
        if (active != null && active != token && byToken.containsKey(active)) {
            // Another prompt is on screen: keep this one queued (notification only).
            return true
        }
        val now = System.currentTimeMillis()
        val previous = lastPromptLaunchMs[token] ?: 0L
        if (now - previous < RELAUNCH_THROTTLE_MS) return false
        lastPromptLaunchMs[token] = now
        activeToken = token
        try {
            val intent = AppAccessRequestActivity.buildIntent(context, token).apply {
                addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
            }
            context.startActivity(intent)
            DiagnosticLogger.logServiceEvent(
                "ACCESS_PROMPT_LAUNCHED uid=${request.uid} pkg=${request.packageName ?: "unknown"} network=${request.network.displayName} protocol=$protocolLabel pending=${byToken.size}"
            )
            return true
        } catch (e: Exception) {
            // Keep the request and notification alive. A later packet will retry the
            // visible Activity launch after the throttle window.
            if (activeToken == token) activeToken = null
            DiagnosticLogger.logServiceEvent(
                "ACCESS_PROMPT_DIRECT_LAUNCH_FAILED uid=${request.uid} pkg=${request.packageName ?: "unknown"} err=${e.javaClass.simpleName}"
            )
            return false
        }
    }

    private fun schedulePromptWatchdog(context: Context, request: Request) {
        val token = request.token
        if (promptWatchdogs.containsKey(token)) return
        val startedAt = System.currentTimeMillis()
        val future = promptExecutor.scheduleAtFixedRate({
            val live = byToken[token]
            if (live == null || System.currentTimeMillis() - startedAt >= PROMPT_WATCHDOG_MAX_MS) {
                promptWatchdogs.remove(token)?.cancel(false)
                return@scheduleAtFixedRate
            }
            if (launchPromptActivity(context.applicationContext, token, live, "WATCHDOG")) {
                promptWatchdogs.remove(token)?.cancel(false)
            }
        }, PROMPT_WATCHDOG_PERIOD_MS, PROMPT_WATCHDOG_PERIOD_MS, TimeUnit.MILLISECONDS)
        promptWatchdogs[token] = future
        DiagnosticLogger.logServiceEvent(
            "ACCESS_PROMPT_WATCHDOG_SCHEDULED uid=${request.uid} pkg=${request.packageName ?: "unknown"} token=$token"
        )
    }

    private fun cancelPromptWatchdog(token: String) {
        promptWatchdogs.remove(token)?.cancel(false)
    }

    /**
     * Remove any queued prompts for a UID. Used when entering a controlled
     * self-test so a stale notification from the restart race cannot survive
     * and ask the user about HYDRA itself.
     */
    fun cancelUid(uid: Int) {
        val removed = synchronized(this) {
            val targets = byToken.values.filter { it.uid == uid }.distinctBy { it.token }
            targets.forEach { request ->
                request.sessionKeys.forEach { byKey.remove(it) }
                byPromptKey.remove(request.promptKey)
                byToken.remove(request.token)
                endRequest(request.token)
            }
            targets
        }
        if (removed.isNotEmpty()) {
            val ctx = contextRef
            removed.forEach { request ->
                ctx?.let { NotificationHelper.clearAccessRequestNotification(it, request.token) }
            }
            DiagnosticLogger.logServiceEvent(
                "ACCESS_PROMPTS_CANCELLED_UID uid=$uid count=${removed.size}"
            )
        }
    }

    /** Re-publish all pending request notifications after the VPN service is recreated.
     * The requests themselves remain in memory while the app process is alive; the
     * notification must be recreated so a service restart cannot hide the queue.
     */
    fun restorePendingNotifications(context: Context) {
        contextRef = context.applicationContext
        val pending = synchronized(this) { byToken.values.toList() }
        pending.forEach { request ->
            NotificationHelper.notifyAccessRequest(
                context = context.applicationContext,
                token = request.token,
                packageName = request.packageName,
                uid = request.uid,
                network = request.network,
                pendingCount = pending.size,
                attemptCount = request.attempts.size
            )
        }
        if (pending.isNotEmpty()) {
            DiagnosticLogger.logServiceEvent(
                "ACCESS_PROMPTS_RESTORED count=${pending.size}"
            )
        }
    }

    /** Number of access requests currently waiting on a user decision. */
    fun pendingCount(): Int = byToken.size

    enum class Persistence { ONCE, ALWAYS, TEMP_10_MIN, TEMP_60_MIN, ESSENTIAL }

    fun resolve(token: String, wifiAllowed: Boolean, mobileAllowed: Boolean, persistence: Persistence = Persistence.ALWAYS) {
        val request = synchronized(this) {
            val r = byToken.remove(token) ?: return
            r.sessionKeys.forEach { byKey.remove(it) }
            byPromptKey.remove(r.promptKey)
            markResolved(r.promptKey)
            endRequest(r.token)
            lastPromptLaunchMs.remove(r.token)
            cancelPromptWatchdog(r.token)
            r
        }
        contextRef?.let { ctx ->
            NotificationHelper.clearAccessRequestNotification(ctx, request.token)
            val store = RuleStore(ctx)
            AppCompatibilityPolicyStore.init(ctx)
            // Every in-VPN decision is mutually exclusive with both compatibility
            // modes. Re-enter NORMAL before applying an ESSENTIAL target only when
            // necessary; otherwise one action could create two VPN rebuilds.
            if (request.packageName != null && persistence != Persistence.ESSENTIAL) {
                val previous = AppCompatibilityPolicyStore.getMode(request.packageName)
                if (previous != AppCompatibilityMode.NORMAL) {
                    AppCompatibilityController.setModeAndRestart(ctx, request.packageName, AppCompatibilityMode.NORMAL)
                }
            }
            val effectiveLabel = when (persistence) {
                Persistence.ONCE -> "ONCE"
                Persistence.ALWAYS -> "ALWAYS"
                Persistence.TEMP_10_MIN -> "TEMP_10_MIN"
                Persistence.TEMP_60_MIN -> "TEMP_60_MIN"
                Persistence.ESSENTIAL -> "ESSENTIAL"
            }
            if (persistence == Persistence.ESSENTIAL) {
                // Essential is explicit and mutually exclusive with SIN FIREWALL.
                // Persist the Wi-Fi/Mobile choice first, then synchronize the
                // compatibility mode so a former EXCLUDED app is re-included in
                // the VPN with one controlled rebuild.
                store.setWifiAllowed(request.uid, wifiAllowed)
                store.setMobileAllowed(request.uid, mobileAllowed)
                request.packageName?.takeIf { it.isNotBlank() }?.let { pkg ->
                    AppCompatibilityController.setModeAndRestart(ctx, pkg, AppCompatibilityMode.ESSENTIAL)
                } ?: EssentialAppsStore(ctx).setUserEssential(request.uid, true)
                DecisionHistory.record(
                    context = ctx,
                    token = request.token,
                    uid = request.uid,
                    packageName = request.packageName,
                    oldWifi = request.initialWifiAllowed,
                    oldMobile = request.initialMobileAllowed,
                    newWifi = wifiAllowed,
                    newMobile = mobileAllowed
                )
            } else if (persistence == Persistence.ALWAYS) {
                DecisionHistory.record(
                    context = ctx,
                    token = request.token,
                    uid = request.uid,
                    packageName = request.packageName,
                    oldWifi = request.initialWifiAllowed,
                    oldMobile = request.initialMobileAllowed,
                    newWifi = wifiAllowed,
                    newMobile = mobileAllowed
                )
            } else {
                val duration = when (persistence) {
                    Persistence.TEMP_10_MIN -> 10L * 60_000L
                    Persistence.TEMP_60_MIN -> 60L * 60_000L
                    Persistence.ONCE, Persistence.ALWAYS, Persistence.ESSENTIAL -> 0L
                }
                if (persistence != Persistence.ONCE) store.setTemporaryRule(request.uid, wifiAllowed, mobileAllowed, duration)
            }
            DiagnosticLogger.logServiceEvent("ACCESS_DECISION_APPLIED persistence=$effectiveLabel uid=${request.uid}")
        }
        request.onDecision(wifiAllowed, mobileAllowed)
        DiagnosticLogger.logServiceEvent(
            "ACCESS_DECISION uid=${request.uid} pkg=${request.packageName ?: "unknown"} wifi=$wifiAllowed mobile=$mobileAllowed"
        )
    }


    fun resolveCustom(
        token: String,
        wifiAllowed: Boolean,
        mobileAllowed: Boolean,
        profile: CustomProtectionProfileStore.Profile
    ) {
        val request = synchronized(this) {
            val r = byToken.remove(token) ?: return
            r.sessionKeys.forEach { byKey.remove(it) }
            byPromptKey.remove(r.promptKey)
            markResolved(r.promptKey)
            endRequest(r.token)
            lastPromptLaunchMs.remove(r.token)
            cancelPromptWatchdog(r.token)
            r
        }
        contextRef?.let { ctx ->
            NotificationHelper.clearAccessRequestNotification(ctx, request.token)
            val store = RuleStore(ctx)
            store.setWifiAllowed(request.uid, wifiAllowed)
            store.setMobileAllowed(request.uid, mobileAllowed)
            CustomProtectionProfileStore(ctx).set(request.uid, profile)
            request.packageName?.takeIf { it.isNotBlank() }?.let { pkg ->
                AppCompatibilityController.setModeAndRestart(ctx, pkg, AppCompatibilityMode.CUSTOM)
            }
            DecisionHistory.record(
                context = ctx,
                token = request.token,
                uid = request.uid,
                packageName = request.packageName,
                oldWifi = request.initialWifiAllowed,
                oldMobile = request.initialMobileAllowed,
                newWifi = wifiAllowed,
                newMobile = mobileAllowed
            )
            DiagnosticLogger.logServiceEvent(
                "ACCESS_DECISION_APPLIED persistence=CUSTOM uid=${request.uid} pkg=${request.packageName ?: "unknown"}"
            )
        }
        request.onDecision(wifiAllowed, mobileAllowed)
        DiagnosticLogger.logServiceEvent(
            "ACCESS_DECISION_CUSTOM uid=${request.uid} pkg=${request.packageName ?: "unknown"} wifi=$wifiAllowed mobile=$mobileAllowed"
        )
    }


    /**
     * Moves an app completely outside the VPN. No firewall rule is written
     * here: when the user later returns the app to NORMAL, its previous
     * Wi-Fi/Mobile policy remains intact (or it can prompt again if none existed).
     */
    fun resolveNoFirewall(token: String) {
        val request = synchronized(this) {
            val r = byToken.remove(token) ?: return
            r.sessionKeys.forEach { byKey.remove(it) }
            byPromptKey.remove(r.promptKey)
            markResolved(r.promptKey)
            endRequest(r.token)
            lastPromptLaunchMs.remove(r.token)
            cancelPromptWatchdog(r.token)
            r
        }
        contextRef?.let { ctx ->
            if (!request.packageName.isNullOrBlank()) {
                AppCompatibilityController.setModeAndRestart(
                    ctx,
                    request.packageName,
                    AppCompatibilityMode.EXCLUDED
                )
            }
            NotificationHelper.clearAccessRequestNotification(ctx, request.token)
            DiagnosticLogger.logServiceEvent(
                "ACCESS_DECISION_NO_FIREWALL uid=${request.uid} pkg=${request.packageName ?: "unknown"}"
            )
        }
        // FIX128: do NOT call request.onDecision here. That callback persists
        // explicit Wi-Fi/Mobile rules, which would silently turn the app into
        // "allowed everywhere" when it later returns to NORMAL. The pending
        // packet is discarded; once the VPN restarts the app bypasses the TUN.
    }

    fun cancel(token: String) {
        synchronized(this) {
            val r = byToken.remove(token) ?: return
            r.sessionKeys.forEach { byKey.remove(it) }
            byPromptKey.remove(r.promptKey)
            lastPromptLaunchMs.remove(r.token)
            cancelPromptWatchdog(r.token)
            endRequest(r.token)
            contextRef?.let { ctx ->
                NotificationHelper.clearAccessRequestNotification(ctx, r.token)
                byToken.values.forEach { pending ->
                    NotificationHelper.notifyAccessRequest(ctx, pending.token, pending.packageName, pending.uid, pending.network, byToken.size, pending.attempts.size)
                }
            }
        }
    }

    private fun formatEndpoint(addr: java.net.InetAddress, port: Int): String {
        val host = addr.hostAddress ?: "?"
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
}
