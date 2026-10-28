package com.hydra.firewall.vpn

import android.content.Context

/**
 * Per-application VPN compatibility profile.
 *
 * NORMAL    = app remains in HYDRA with normal policy.
 * ESSENTIAL = app remains in HYDRA with the normal compatibility bypasses.
 * ESSENTIAL_COMPAT = temporary diagnostic compatibility mode: app stays in HYDRA
 *                    but optional domain/ad-tracker/QUIC filters are bypassed;
 *                    explicit user blocks and confirmed threat controls remain.
 * EXCLUDED  = app is completely outside the firewall/VPN via
 *             addDisallowedApplication(). The UI calls this NO FIREWALL.
 *
 * Compatibility is intentionally kept separate from trust/security. An app being
 * incompatible with a VPN does not mean that the app is safe or trusted.
 */
enum class AppCompatibilityMode { NORMAL, CUSTOM, ESSENTIAL, ESSENTIAL_COMPAT, EXCLUDED }

object AppCompatibilityPolicyStore {
    private const val PREFS = "app_compatibility_policy"
    private const val KEY_MODE_PREFIX = "mode_"
    private const val LEGACY_PROTECTED_PREFIX = "protected_compat_"
    // One-time cleanup for the retired Mercado Pago diagnostic mode from the
    // beta builds. This does not affect any later user choice: after the first
    // final build starts, the normal SIN FIREWALL control is fully user-owned.
    private const val FINAL_MP_CLEANUP_KEY = "final_1_5_beta6_mp_cleanup_v1"
    private const val MERCADO_PAGO_PACKAGE = "com.mercadopago.wallet"

    private lateinit var prefs: android.content.SharedPreferences

    /**
     * Public reference candidates based on the behavior documented by
     * TrackerControl / DuckDuckGo: browsers and some web-content/system apps are
     * commonly excluded because local VPN interception can break them.
     * This is NOT an Android system trust list and nothing here is auto-excluded.
     */
    private val knownReferencePackages = mapOf(
        "com.android.chrome" to "Referencia: navegador / posible incompatibilidad VPN",
        "org.mozilla.firefox" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.microsoft.emmx" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.brave.browser" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.opera.browser" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.sec.android.app.sbrowser" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.duckduckgo.mobile.android" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.vivaldi.browser" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.kiwibrowser.browser" to "Referencia: navegador / posible incompatibilidad VPN",
        "com.google.android.projection.gearhead" to "Referencia: Android Auto / compatibilidad de red"
    )

    @Synchronized
    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        // Migrate the previous FIX116/120 boolean profile to the new explicit mode.
        prefs.all.keys
            .filter { it.startsWith(LEGACY_PROTECTED_PREFIX) }
            .forEach { legacyKey ->
                val pkg = legacyKey.removePrefix(LEGACY_PROTECTED_PREFIX)
                if (!prefs.contains(KEY_MODE_PREFIX + pkg)) {
                    val enabled = prefs.getBoolean(legacyKey, false)
                    if (enabled) prefs.edit().putString(KEY_MODE_PREFIX + pkg, AppCompatibilityMode.ESSENTIAL.name).apply()
                }
            }


        // Retire the old beta Mercado Pago diagnostic selection exactly once.
        // Previous beta builds used the same SharedPreferences namespace, so an
        // in-place upgrade could otherwise make MP appear as SIN FIREWALL by
        // default even though the final product has no MP-specific mode.
        if (!prefs.getBoolean(FINAL_MP_CLEANUP_KEY, false)) {
            prefs.edit().remove(KEY_MODE_PREFIX + MERCADO_PAGO_PACKAGE)
                .putBoolean(FINAL_MP_CLEANUP_KEY, true)
                .commit()
        }

        // NO FIREWALL and user ESSENTIAL are mutually exclusive. If an older
        // build left both flags enabled, the app is now outside the TUN, so
        // clear the redundant Essential flag at startup.
        val essentialStore = EssentialAppsStore(context.applicationContext)
        prefs.all
            .filterKeys { it.startsWith(KEY_MODE_PREFIX) }
            .forEach { (key, value) ->
                if ((value as? String) == AppCompatibilityMode.EXCLUDED.name) {
                    val pkg = key.removePrefix(KEY_MODE_PREFIX)
                    runCatching { context.applicationContext.packageManager.getApplicationInfo(pkg, 0).uid }
                        .onSuccess { uid -> essentialStore.setUserEssential(uid, false) }
                }
            }
    }

    fun getMode(packageName: String?): AppCompatibilityMode {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty() || !::prefs.isInitialized) return AppCompatibilityMode.NORMAL
        return runCatching {
            AppCompatibilityMode.valueOf(prefs.getString(KEY_MODE_PREFIX + pkg, AppCompatibilityMode.NORMAL.name)!!)
        }.getOrDefault(AppCompatibilityMode.NORMAL)
    }

    fun setMode(packageName: String, mode: AppCompatibilityMode) {
        if (!::prefs.isInitialized) return
        val pkg = packageName.trim()
        if (pkg.isEmpty()) return
        // Persist synchronously before a VPN re-establishment. This matters on
        // Android 7 because the service rebuilds its Builder immediately after
        // the compatibility action; using commit() guarantees the new mode is
        // visible to that same-process service before addDisallowedApplication().
        prefs.edit().putString(KEY_MODE_PREFIX + pkg, mode.name).commit()
    }

    fun isProtectedCompatibility(packageName: String?): Boolean =
        getMode(packageName) == AppCompatibilityMode.ESSENTIAL ||
        getMode(packageName) == AppCompatibilityMode.ESSENTIAL_COMPAT

    fun isExcluded(packageName: String?): Boolean =
        getMode(packageName) == AppCompatibilityMode.EXCLUDED

    fun excludedPackages(): Set<String> {
        if (!::prefs.isInitialized) return emptySet()
        return prefs.all
            .filterKeys { it.startsWith(KEY_MODE_PREFIX) }
            .mapNotNull { (key, value) ->
                if ((value as? String) == AppCompatibilityMode.EXCLUDED.name) {
                    key.removePrefix(KEY_MODE_PREFIX).takeIf { it.isNotBlank() }
                } else null
            }.toSet()
    }

    fun isKnownReference(packageName: String?): Boolean =
        packageName?.trim()?.let { knownReferencePackages.containsKey(it) } == true

    fun referenceReason(packageName: String?): String? =
        packageName?.trim()?.let { knownReferencePackages[it] }

    fun snapshot(): Map<String, Boolean> =
        snapshotModes().mapValues {
            it.value == AppCompatibilityMode.ESSENTIAL || it.value == AppCompatibilityMode.ESSENTIAL_COMPAT
        }

    fun snapshotModes(): Map<String, AppCompatibilityMode> {
        if (!::prefs.isInitialized) return emptyMap()
        return prefs.all
            .filterKeys { it.startsWith(KEY_MODE_PREFIX) }
            .mapNotNull { (key, value) ->
                val pkg = key.removePrefix(KEY_MODE_PREFIX)
                val mode = runCatching { AppCompatibilityMode.valueOf(value as? String ?: "NORMAL") }.getOrDefault(AppCompatibilityMode.NORMAL)
                if (pkg.isBlank() || mode == AppCompatibilityMode.NORMAL) null else pkg to mode
            }.toMap()
    }
}
