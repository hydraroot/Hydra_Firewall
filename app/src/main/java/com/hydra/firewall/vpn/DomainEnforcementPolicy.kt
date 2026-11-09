package com.hydra.firewall.vpn

/**
 * Shared domain-policy decisions for both address families.
 *
 * IPv4 and IPv6 have different packet formats, but they must not disagree on
 * threat precedence, explicit user rules, optional blocklists or SNI settings.
 * This class is deliberately pure so the decision table is easy to test.
 */
internal object DomainEnforcementPolicy {
    /**
     * @param threatMatched a signed threat-intelligence match (always authoritative)
     * @param customRuleBlocks true = explicit BLOCK, false = explicit ALLOW, null = no rule
     */
    fun shouldBlockDns(
        threatMatched: Boolean,
        customRuleBlocks: Boolean?,
        publicBlocklisted: Boolean,
        bypassOptionalBlocklist: Boolean
    ): Boolean {
        if (threatMatched) return true
        if (customRuleBlocks != null) return customRuleBlocks
        return publicBlocklisted && !bypassOptionalBlocklist
    }

    /** SNI protection is an additional switch for the public blocklist only. */
    fun shouldBlockTlsSni(
        threatMatched: Boolean,
        customRuleBlocks: Boolean?,
        publicBlocklisted: Boolean,
        bypassOptionalBlocklist: Boolean,
        sniProtectionEnabled: Boolean
    ): Boolean {
        if (threatMatched) return true
        if (customRuleBlocks != null) return customRuleBlocks
        return publicBlocklisted && !bypassOptionalBlocklist && sniProtectionEnabled
    }
}
