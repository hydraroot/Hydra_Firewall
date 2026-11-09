package com.hydra.firewall.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Regression tests for the shared IPv4/IPv6 DNS and TLS-SNI policy. */
class DomainEnforcementPolicyTest {
    @Test
    fun signedThreatAlwaysWinsOverUserAllowAndCompatibilityBypass() {
        assertTrue(
            DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = true,
                customRuleBlocks = false,
                publicBlocklisted = false,
                bypassOptionalBlocklist = true
            )
        )
        assertTrue(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = true,
                customRuleBlocks = false,
                publicBlocklisted = false,
                bypassOptionalBlocklist = true,
                sniProtectionEnabled = false
            )
        )
    }

    @Test
    fun explicitBlockOverridesOptionalBlocklistBypass() {
        assertTrue(
            DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = false,
                customRuleBlocks = true,
                publicBlocklisted = false,
                bypassOptionalBlocklist = true
            )
        )
        assertTrue(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = true,
                publicBlocklisted = false,
                bypassOptionalBlocklist = true,
                sniProtectionEnabled = false
            )
        )
    }

    @Test
    fun explicitAllowOverridesPublicBlocklistButNotSignedThreat() {
        assertFalse(
            DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = false,
                customRuleBlocks = false,
                publicBlocklisted = true,
                bypassOptionalBlocklist = false
            )
        )
        assertFalse(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = false,
                publicBlocklisted = true,
                bypassOptionalBlocklist = false,
                sniProtectionEnabled = true
            )
        )
    }

    @Test
    fun compatibilityBypassOnlySkipsThePublicBlocklist() {
        assertFalse(
            DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = true,
                bypassOptionalBlocklist = true
            )
        )
        assertFalse(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = true,
                bypassOptionalBlocklist = true,
                sniProtectionEnabled = true
            )
        )
    }

    @Test
    fun sniSwitchControlsOnlyThePublicBlocklist() {
        assertFalse(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = true,
                bypassOptionalBlocklist = false,
                sniProtectionEnabled = false
            )
        )
        assertTrue(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = true,
                bypassOptionalBlocklist = false,
                sniProtectionEnabled = true
            )
        )
    }

    @Test
    fun nonBlocklistedDomainIsAllowedByBothFamiliesPolicy() {
        assertFalse(
            DomainEnforcementPolicy.shouldBlockDns(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = false,
                bypassOptionalBlocklist = false
            )
        )
        assertFalse(
            DomainEnforcementPolicy.shouldBlockTlsSni(
                threatMatched = false,
                customRuleBlocks = null,
                publicBlocklisted = false,
                bypassOptionalBlocklist = false,
                sniProtectionEnabled = true
            )
        )
    }
}
