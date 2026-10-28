package com.hydra.firewall.vpn

import android.os.Process
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleEngineDnsTest {
    private val configured = setOf("192.168.1.1", "1.1.1.1")

    @Test
    fun systemUidPort53AllowedForConfiguredResolverOrLocalResolver() {
        assertTrue(RuleEngine.shouldAllowSystemDns(0, 53, "192.168.1.1", configured))
        assertTrue(RuleEngine.shouldAllowSystemDns(9999, 53, "1.1.1.1", configured))
    }

    @Test
    fun systemUidPort53BlockedForArbitraryDnsDestination() {
        assertFalse(RuleEngine.shouldAllowSystemDns(0, 53, "8.8.8.8", configured))
        assertTrue(RuleEngine.shouldAllowSystemDns(0, 53, "192.168.1.53", configured))
    }

    @Test
    fun applicationUidDoesNotGetSystemDnsException() {
        assertFalse(RuleEngine.shouldAllowSystemDns(Process.FIRST_APPLICATION_UID, 53, "192.168.1.1", configured))
        assertFalse(RuleEngine.shouldAllowSystemDns(10120, 53, "192.168.1.1", configured))
    }

    @Test
    fun nonDnsPortDoesNotGetSystemDnsException() {
        assertFalse(RuleEngine.shouldAllowSystemDns(0, 443, "192.168.1.1", configured))
    }

    @Test
    fun systemDnsAllowsPrivateRouterByDefault() {
        val configured = emptySet<String>()
        assertTrue(RuleEngine.shouldAllowSystemDns(0, 53, "192.168.1.1", configured))
        assertTrue(RuleEngine.shouldAllowSystemDns(0, 53, "10.0.0.1", configured))
        assertTrue(RuleEngine.shouldAllowSystemDns(0, 53, "172.16.0.1", configured))
    }

    @Test
    fun appUidsCannotUseSystemDnsDefaultException() {
        val configured = emptySet<String>()
        assertFalse(RuleEngine.shouldAllowSystemDns(10120, 53, "192.168.1.1", configured))
    }
}
