package com.hydra.firewall.vpn

import android.content.Context

/**
 * Built-in DNS-over-TLS providers plus a user-defined custom endpoint.
 * CLOUDFLARE is the default: it is the historically fastest/most reliable
 * public DoT anycast network and requires no configuration.
 */
enum class DnsProvider { CLOUDFLARE, GOOGLE, QUAD9, CUSTOM }

enum class DnsTransport { DOT, DOH }

data class DnsProviderConfig(
    val ipv4: List<String>,
    val ipv6: List<String>,
    val tlsHostname: String,
    val dohUrl: String? = null
)

/** Persistent per-UID policy plus defaults for previously unseen UIDs. */
class RuleStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    init {
        // FIX114: the UI/help text promises explicit app permission in the
        // default strict mode. Older builds accidentally stored ALLOW as the
        // default, so every app appeared permitted even before a rule existed.
        // This only changes the default for previously unseen UIDs; explicit
        // per-UID rules are never modified.
        migrateLegacyDefaultAllow()
    }

    data class Rule(
        val wifiAllowed: Boolean = false,
        val mobileAllowed: Boolean = false
    )

    data class Schedule(
        val enabled: Boolean = false,
        val startMinutes: Int = 22 * 60,
        val endMinutes: Int = 7 * 60,
        val daysMask: Int = 0b1111111
    )

    /** Policy for a UID without an explicit per-UID rule. */
    var defaultWifiAllowed: Boolean
        get() = prefs.getBoolean(KEY_DEFAULT_WIFI, false)
        set(value) { prefs.edit().putBoolean(KEY_DEFAULT_WIFI, value).apply() }

    var defaultMobileAllowed: Boolean
        get() = prefs.getBoolean(KEY_DEFAULT_MOBILE, false)
        set(value) { prefs.edit().putBoolean(KEY_DEFAULT_MOBILE, value).apply() }

    /** Ask before allowing a UID that has no explicit per-UID rule. */
    var askOnFirstConnection: Boolean
        get() = prefs.getBoolean(KEY_ASK_FIRST, true)
        set(value) { prefs.edit().putBoolean(KEY_ASK_FIRST, value).apply() }

    /** Analysis-only mode. It never changes allow/block decisions; it enables
     * richer traffic insights and rule suggestions in the UI. */
    var learningMode: Boolean
        get() = prefs.getBoolean(KEY_LEARNING_MODE, false)
        set(value) { prefs.edit().putBoolean(KEY_LEARNING_MODE, value).apply() }

    /** Safety policy when the UID resolver cannot attribute a packet.
     *  Default is BLOCK (false): a firewall should fail closed, not open,
     *  when it cannot attribute a packet to an app. */
    var invalidUidAllowed: Boolean
        get() = prefs.getBoolean(KEY_INVALID_UID_ALLOWED, false)
        set(value) { prefs.edit().putBoolean(KEY_INVALID_UID_ALLOWED, value).apply() }

    /**
     * A quarantine-created BLOCK/BLOCK is not a user decision. It must remain
     * fail-closed on the wire, but it must still be eligible for the first-
     * connection prompt so the user can review the app.
     */
    fun hasExplicitRule(uid: Int): Boolean =
        (prefs.contains("uid_${uid}_wifi") || prefs.contains("uid_${uid}_mobile")) &&
            !prefs.getBoolean("uid_${uid}_quarantine_default", false)

    fun isQuarantineDefault(uid: Int): Boolean =
        prefs.getBoolean("uid_${uid}_quarantine_default", false)

    fun setQuarantineDefault(uid: Int) {
        prefs.edit()
            .putBoolean("uid_${uid}_wifi", false)
            .putBoolean("uid_${uid}_mobile", false)
            .putBoolean("uid_${uid}_quarantine_default", true)
            .apply()
    }

    fun getRule(uid: Int): Rule = Rule(
        wifiAllowed = prefs.getBoolean("uid_${uid}_wifi", defaultWifiAllowed),
        mobileAllowed = prefs.getBoolean("uid_${uid}_mobile", defaultMobileAllowed)
    )

    fun setWifiAllowed(uid: Int, allowed: Boolean) {
        prefs.edit()
            .putBoolean("uid_${uid}_wifi", allowed)
            .remove("uid_${uid}_quarantine_default")
            .apply()
    }

    fun setMobileAllowed(uid: Int, allowed: Boolean) {
        prefs.edit()
            .putBoolean("uid_${uid}_mobile", allowed)
            .remove("uid_${uid}_quarantine_default")
            .apply()
    }

    fun clearRule(uid: Int) {
        prefs.edit()
            .remove("uid_${uid}_wifi")
            .remove("uid_${uid}_mobile")
            .remove("uid_${uid}_quarantine_default")
            .apply()
    }


    var threatProtectionEnabled: Boolean
        get() = prefs.getBoolean(KEY_THREAT_PROTECTION, false)
        set(value) { prefs.edit().putBoolean(KEY_THREAT_PROTECTION, value).apply() }

    var secureDnsEnabled: Boolean
        get() = prefs.getBoolean(KEY_SECURE_DNS, true)
        set(value) { prefs.edit().putBoolean(KEY_SECURE_DNS, value).apply() }

    /** Selected encrypted DNS provider. Defaults to Cloudflare. */
    var dnsProvider: DnsProvider
        get() = runCatching { DnsProvider.valueOf(prefs.getString(KEY_DNS_PROVIDER, DnsProvider.CLOUDFLARE.name)!!) }
            .getOrDefault(DnsProvider.CLOUDFLARE)
        set(value) { prefs.edit().putString(KEY_DNS_PROVIDER, value.name).apply() }

    /** Encrypted DNS transport. DoT is kept as the default for Android 7 compatibility. */
    var dnsTransport: DnsTransport
        get() = runCatching { DnsTransport.valueOf(prefs.getString(KEY_DNS_TRANSPORT, DnsTransport.DOT.name)!!) }
            .getOrDefault(DnsTransport.DOT)
        set(value) { prefs.edit().putString(KEY_DNS_TRANSPORT, value.name).apply() }

    var customDnsIpv4: String
        get() = prefs.getString(KEY_CUSTOM_DNS_IPV4, "") ?: ""
        set(value) { prefs.edit().putString(KEY_CUSTOM_DNS_IPV4, value.trim()).apply() }

    var customDnsIpv6: String
        get() = prefs.getString(KEY_CUSTOM_DNS_IPV6, "") ?: ""
        set(value) { prefs.edit().putString(KEY_CUSTOM_DNS_IPV6, value.trim()).apply() }

    var customDnsHostname: String
        get() = prefs.getString(KEY_CUSTOM_DNS_HOSTNAME, "") ?: ""
        set(value) { prefs.edit().putString(KEY_CUSTOM_DNS_HOSTNAME, value.trim()).apply() }

    var customDnsDohUrl: String
        get() = prefs.getString(KEY_CUSTOM_DNS_DOH_URL, "") ?: ""
        set(value) { prefs.edit().putString(KEY_CUSTOM_DNS_DOH_URL, value.trim()).apply() }

    /** Resolves the active provider's connection config, falling back to
     *  Cloudflare if CUSTOM is selected but incompletely configured. */
    fun activeDnsProviderConfig(): DnsProviderConfig {
        val provider = dnsProvider
        if (threatProtectionEnabled) return DNS_CLOUDFLARE_SECURITY
        return when (provider) {
            DnsProvider.CLOUDFLARE -> DNS_CLOUDFLARE
            DnsProvider.GOOGLE -> DNS_GOOGLE
            DnsProvider.QUAD9 -> DNS_QUAD9
            DnsProvider.CUSTOM -> {
                val ipv4 = customDnsIpv4.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                val ipv6 = customDnsIpv6.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                val hostname = customDnsHostname.trim()
                val dohUrl = customDnsDohUrl.trim().takeIf { it.startsWith("https://", ignoreCase = true) }
                if ((ipv4.isNotEmpty() || ipv6.isNotEmpty()) && hostname.isNotEmpty()) {
                    DnsProviderConfig(ipv4, ipv6, hostname, dohUrl)
                } else {
                    DNS_CLOUDFLARE
                }
            }
        }
    }

    fun getSchedule(uid: Int): Schedule = Schedule(
        enabled = prefs.getBoolean("uid_${uid}_schedule_enabled", false),
        startMinutes = prefs.getInt("uid_${uid}_schedule_start", 22 * 60).coerceIn(0, 1439),
        endMinutes = prefs.getInt("uid_${uid}_schedule_end", 7 * 60).coerceIn(0, 1439),
        daysMask = prefs.getInt("uid_${uid}_schedule_days", 0b1111111) and 0b1111111
    )

    fun setSchedule(uid: Int, schedule: Schedule) {
        prefs.edit()
            .putBoolean("uid_${uid}_schedule_enabled", schedule.enabled)
            .putInt("uid_${uid}_schedule_start", schedule.startMinutes.coerceIn(0, 1439))
            .putInt("uid_${uid}_schedule_end", schedule.endMinutes.coerceIn(0, 1439))
            .putInt("uid_${uid}_schedule_days", schedule.daysMask and 0b1111111)
            .apply()
    }

    var policyMode: String
        get() = prefs.getString(KEY_POLICY_MODE, "BLACKLIST") ?: "BLACKLIST"
        set(value) { prefs.edit().putString(KEY_POLICY_MODE, value).apply() }

    var allowLocalNetwork: Boolean
        get() = prefs.getBoolean(KEY_ALLOW_LOCAL, true)
        set(value) { prefs.edit().putBoolean(KEY_ALLOW_LOCAL, value).apply() }

    /** Descarta todo el tráfico IPv6 en el túnel: las apps caen a IPv4 y quedan sujetas a los filtros IPv4. */
    var blockIpv6: Boolean
        get() = prefs.getBoolean(KEY_BLOCK_IPV6, false)
        set(value) { prefs.edit().putBoolean(KEY_BLOCK_IPV6, value).apply() }

    var blockWhenScreenOff: Boolean
        get() = prefs.getBoolean(KEY_BLOCK_SCREEN_OFF, false)
        set(value) { prefs.edit().putBoolean(KEY_BLOCK_SCREEN_OFF, value).apply() }

    var blockWhenRoaming: Boolean
        get() = prefs.getBoolean(KEY_BLOCK_ROAMING, false)
        set(value) { prefs.edit().putBoolean(KEY_BLOCK_ROAMING, value).apply() }

    var globalBlockAll: Boolean
        get() = prefs.getBoolean(KEY_GLOBAL_BLOCK_ALL, false)
        set(value) { prefs.edit().putBoolean(KEY_GLOBAL_BLOCK_ALL, value).apply() }



    data class TemporaryRule(val wifiAllowed: Boolean, val mobileAllowed: Boolean, val expiresAt: Long)

    fun getTemporaryRule(uid: Int, nowMillis: Long = System.currentTimeMillis()): TemporaryRule? {
        val expires = prefs.getLong("uid_${uid}_temp_expires", 0L)
        if (expires <= nowMillis) {
            clearTemporaryRule(uid)
            return null
        }
        return TemporaryRule(
            prefs.getBoolean("uid_${uid}_temp_wifi", true),
            prefs.getBoolean("uid_${uid}_temp_mobile", true),
            expires
        )
    }

    fun setTemporaryRule(uid: Int, wifiAllowed: Boolean, mobileAllowed: Boolean, durationMillis: Long) {
        val expires = System.currentTimeMillis() + durationMillis.coerceAtLeast(1L)
        prefs.edit()
            .putBoolean("uid_${uid}_temp_wifi", wifiAllowed)
            .putBoolean("uid_${uid}_temp_mobile", mobileAllowed)
            .putLong("uid_${uid}_temp_expires", expires)
            .apply()
    }

    fun clearTemporaryRule(uid: Int) {
        prefs.edit()
            .remove("uid_${uid}_temp_wifi")
            .remove("uid_${uid}_temp_mobile")
            .remove("uid_${uid}_temp_expires")
            .apply()
    }

    data class SnapshotEntry(val uid: Int, val wifiAllowed: Boolean, val mobileAllowed: Boolean, val scheduleEnabled: Boolean, val startMinutes: Int, val endMinutes: Int, val daysMask: Int)

    fun ruleSnapshotEntries(): List<SnapshotEntry> = prefs.all.keys.filter { it.startsWith("uid_") && it.endsWith("_wifi") }.mapNotNull { key ->
        val uid = key.removePrefix("uid_").removeSuffix("_wifi").toIntOrNull() ?: return@mapNotNull null
        val s = getSchedule(uid); val r = getRule(uid)
        SnapshotEntry(uid, r.wifiAllowed, r.mobileAllowed, s.enabled, s.startMinutes, s.endMinutes, s.daysMask)
    }.distinctBy { it.uid }.sortedBy { it.uid }

    fun clearRules() {
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith("uid_") }.forEach(editor::remove)
        editor.apply()
    }

    private fun migrateLegacyDefaultAllow() {
        val migrated = prefs.getBoolean(KEY_DEFAULTS_MIGRATED, false)
        if (migrated) return

        val mode = prefs.getString(KEY_POLICY_MODE, "BLACKLIST") ?: "BLACKLIST"
        val legacyDefaults = prefs.getBoolean(KEY_DEFAULT_WIFI, true) ||
            prefs.getBoolean(KEY_DEFAULT_MOBILE, true)

        if (mode == "BLACKLIST" && legacyDefaults) {
            prefs.edit()
                .putBoolean(KEY_DEFAULT_WIFI, false)
                .putBoolean(KEY_DEFAULT_MOBILE, false)
                .putBoolean(KEY_DEFAULTS_MIGRATED, true)
                .apply()
            DiagnosticLogger.logServiceEvent("FIX114 default-app-policy migrated: new apps require explicit permission")
        } else {
            prefs.edit().putBoolean(KEY_DEFAULTS_MIGRATED, true).apply()
        }
    }

    companion object {
        private const val PREFS_NAME = "firewall_rules"
        private const val KEY_DEFAULT_WIFI = "default_wifi_allowed"
        private const val KEY_DEFAULT_MOBILE = "default_mobile_allowed"
        private const val KEY_DEFAULTS_MIGRATED = "fix114_defaults_migrated"
        private const val KEY_INVALID_UID_ALLOWED = "invalid_uid_allowed"
        private const val KEY_ASK_FIRST = "ask_on_first_connection"
        private const val KEY_LEARNING_MODE = "learning_mode"
        private const val KEY_POLICY_MODE = "policy_mode"
        private const val KEY_ALLOW_LOCAL = "allow_local_network"
        private const val KEY_BLOCK_IPV6 = "block_ipv6"
        private const val KEY_BLOCK_SCREEN_OFF = "block_screen_off"
        private const val KEY_BLOCK_ROAMING = "block_roaming"
        private const val KEY_GLOBAL_BLOCK_ALL = "global_block_all"
        private const val KEY_THREAT_PROTECTION = "threat_protection_enabled"
        private const val KEY_SECURE_DNS = "secure_dns_enabled"
        private const val KEY_DNS_PROVIDER = "secure_dns_provider"
        private const val KEY_DNS_TRANSPORT = "secure_dns_transport"
        private const val KEY_CUSTOM_DNS_IPV4 = "secure_dns_custom_ipv4"
        private const val KEY_CUSTOM_DNS_IPV6 = "secure_dns_custom_ipv6"
        private const val KEY_CUSTOM_DNS_HOSTNAME = "secure_dns_custom_hostname"
        private const val KEY_CUSTOM_DNS_DOH_URL = "secure_dns_custom_doh_url"

        // Cloudflare's Malware / Families resolver variant uses its own TLS/DoH
        // hostname. The numeric endpoints 1.1.1.2/1.0.0.2 must not be paired with
        // the generic 1.1.1.1 hostname or DoH endpoint, otherwise certificate
        // validation can fail and the Android 7 client reports a trust/hostname
        // error while the underlying TCP connection is healthy.
        val DNS_CLOUDFLARE_SECURITY = DnsProviderConfig(
            ipv4 = listOf("1.1.1.2", "1.0.0.2"),
            ipv6 = listOf("2606:4700:4700::1112", "2606:4700:4700::1002"),
            tlsHostname = "security.cloudflare-dns.com",
            dohUrl = "https://security.cloudflare-dns.com/dns-query"
        )
        val DNS_CLOUDFLARE = DnsProviderConfig(
            ipv4 = listOf("1.1.1.1", "1.0.0.1"),
            ipv6 = listOf("2606:4700:4700::1111", "2606:4700:4700::1001"),
            tlsHostname = "cloudflare-dns.com",
            dohUrl = "https://cloudflare-dns.com/dns-query"
        )
        val DNS_GOOGLE = DnsProviderConfig(
            ipv4 = listOf("8.8.8.8", "8.8.4.4"),
            ipv6 = listOf("2001:4860:4860::8888", "2001:4860:4860::8844"),
            tlsHostname = "dns.google",
            dohUrl = "https://dns.google/dns-query"
        )
        val DNS_QUAD9 = DnsProviderConfig(
            ipv4 = listOf("9.9.9.9", "149.112.112.112"),
            ipv6 = listOf("2620:fe::fe", "2620:fe::9"),
            tlsHostname = "dns.quad9.net",
            dohUrl = "https://dns.quad9.net/dns-query"
        )
    }
}
