package com.hydra.firewall.security

import android.content.Context
import com.hydra.firewall.vpn.DomainBlockStore
import com.hydra.firewall.vpn.FirewallVpnService
import com.hydra.firewall.vpn.RuleStore

/**
 * Single, explicit view of the protection prerequisites shown on the main screen.
 * The status is deliberately derived from the effective local state, not from
 * whether the user merely has a setting enabled.
 */
object ProtectionStatus {
    enum class Level { ACTIVE, PARTIAL, OFF }

    data class Snapshot(
        val level: Level,
        val vpn: Boolean,
        val dns: Boolean,
        val blocklist: Boolean,
        val rules: Boolean,
        val integrity: Boolean,
        val secureDnsEnabled: Boolean,
        val blocklistEnabled: Boolean,
        val blocklistCount: Int,
        val blocklistSource: String,
        val missing: List<String>
    )

    fun read(context: Context): Snapshot {
        val rulesStore = RuleStore(context)
        val vpn = FirewallVpnService.isRunning
        val secureDnsEnabled = rulesStore.secureDnsEnabled
        val dns = !secureDnsEnabled || vpn

        val listInfo = DomainBlockStore.activeListInfo()
        val blocklistEnabled = DomainBlockStore.enabled
        // If the feature is enabled, a non-empty active list is required. If
        // the feature is disabled by the user, it is reported as disabled but
        // does not artificially turn an otherwise working firewall into PARTIAL.
        val blocklist = !blocklistEnabled || (listInfo.domainCount > 0 && DomainBlockStore.activeListUsable())

        // This is a hardening signal, not a firewall-routing requirement. A
        // debug build can still enforce the VPN rules correctly, so we expose
        // the integrity condition separately instead of treating it as a
        // phantom networking failure.
        val integrityResult = AppIntegrity.inspect(context)
        val integrity = integrityResult.releaseLike

        val missing = mutableListOf<String>().apply {
            if (!vpn) add("VPN")
            if (secureDnsEnabled && !vpn) add("Secure DNS requires the VPN")
            if (blocklistEnabled && !blocklist) add("Active blocklist")
            // App integrity is an informational hardening signal, not a
            // prerequisite for VPN routing/filtering. In particular, a debug
            // build must not make a correctly configured firewall appear PARTIAL.
        }

        val level = when {
            !vpn -> Level.OFF
            vpn && dns && blocklist -> Level.ACTIVE
            else -> Level.PARTIAL
        }

        return Snapshot(
            level = level,
            vpn = vpn,
            dns = dns,
            blocklist = blocklist,
            rules = true,
            integrity = integrity,
            secureDnsEnabled = secureDnsEnabled,
            blocklistEnabled = blocklistEnabled,
            blocklistCount = if (DomainBlockStore.activeListUsable()) listInfo.domainCount else 0,
            blocklistSource = listInfo.source,
            missing = missing
        )
    }
}
