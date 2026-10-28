package com.hydra.firewall.vpn

import android.os.Process
import org.junit.Assert.assertEquals
import org.junit.Test

class RuleEngineSecurityTest {
    @Test
    fun globalBlockAllOverridesAllowUnknownUid() {
        val decision = RuleEngine.precheck(
            Process.INVALID_UID,
            globalBlockAll = true,
            invalidUidAllowed = true,
            essential = false
        )
        assertEquals(RuleEngine.Decision.BLOCK, decision)
    }

    @Test
    fun unknownUidRemainsBlockedByDefault() {
        val decision = RuleEngine.precheck(
            Process.INVALID_UID,
            globalBlockAll = false,
            invalidUidAllowed = false,
            essential = false
        )
        assertEquals(RuleEngine.Decision.BLOCK, decision)
    }

    @Test
    fun unknownUidCanOnlyBeAllowedWhenExplicitlyEnabledAndGlobalBlockIsOff() {
        val decision = RuleEngine.precheck(
            Process.INVALID_UID,
            globalBlockAll = false,
            invalidUidAllowed = true,
            essential = false
        )
        assertEquals(RuleEngine.Decision.ALLOW, decision)
    }

    @Test
    fun globalBlockAllAlsoOverridesEssentialUid() {
        val decision = RuleEngine.precheck(
            uid = 10001,
            globalBlockAll = true,
            invalidUidAllowed = true,
            essential = true
        )
        assertEquals(RuleEngine.Decision.BLOCK, decision)
    }
}
