package com.hydra.firewall.vpn

import android.content.Context

/**
 * Per-UID protection profile used only by PERSONALIZADO mode.
 * Defaults intentionally preserve the existing Hydra protection stack.
 */
class CustomProtectionProfileStore(context: Context) {
    data class Profile(
        val adTrackerBlocklist: Boolean = true,
        val secureDns: Boolean = true,
        val tlsSniFilter: Boolean = true,
        val quicProtection: Boolean = true,
        val tlsFingerprint: Boolean = true,
        val threatProtection: Boolean = true,
        val blockLocalNetwork: Boolean = false
    )

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun get(uid: Int): Profile = Profile(
        adTrackerBlocklist = prefs.getBoolean(key(uid, "ads"), true),
        secureDns = prefs.getBoolean(key(uid, "dns"), true),
        tlsSniFilter = prefs.getBoolean(key(uid, "sni"), true),
        quicProtection = prefs.getBoolean(key(uid, "quic"), true),
        tlsFingerprint = prefs.getBoolean(key(uid, "tls_fp"), true),
        threatProtection = prefs.getBoolean(key(uid, "threat"), true),
        blockLocalNetwork = prefs.getBoolean(key(uid, "local"), false)
    )

    @Synchronized
    fun set(uid: Int, profile: Profile) {
        prefs.edit()
            .putBoolean(key(uid, "ads"), profile.adTrackerBlocklist)
            .putBoolean(key(uid, "dns"), profile.secureDns)
            .putBoolean(key(uid, "sni"), profile.tlsSniFilter)
            .putBoolean(key(uid, "quic"), profile.quicProtection)
            .putBoolean(key(uid, "tls_fp"), profile.tlsFingerprint)
            .putBoolean(key(uid, "threat"), profile.threatProtection)
            .putBoolean(key(uid, "local"), profile.blockLocalNetwork)
            .apply()
    }


    @Synchronized
    fun clearAll() {
        prefs.edit().clear().apply()
    }

    @Synchronized
    fun clear(uid: Int) {
        prefs.edit()
            .remove(key(uid, "ads"))
            .remove(key(uid, "dns"))
            .remove(key(uid, "sni"))
            .remove(key(uid, "quic"))
            .remove(key(uid, "tls_fp"))
            .remove(key(uid, "threat"))
            .remove(key(uid, "local"))
            .apply()
    }

    private fun key(uid: Int, suffix: String): String = "uid_${uid}_$suffix"

    companion object {
        private const val PREFS_NAME = "hydra_custom_protection_profiles"
        fun defaults(): Profile = Profile()
    }
}
