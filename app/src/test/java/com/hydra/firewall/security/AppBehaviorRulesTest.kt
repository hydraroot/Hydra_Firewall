package com.hydra.firewall.security

import org.junit.Assert.*
import org.junit.Test

class AppBehaviorRulesTest {
    private fun facts(req: Set<String> = emptySet(), bound: Set<String> = emptySet(), installer: String? = null, system: Boolean = false) =
        AppBehaviorRules.Facts(req, bound, installer, system)

    @Test fun storeAndSystemAppsAreNeverFlagged() {
        val risky = setOf("READ_SMS", "SYSTEM_ALERT_WINDOW")
        val bound = setOf("BIND_ACCESSIBILITY_SERVICE")
        assertTrue(AppBehaviorRules.evaluate(facts(risky, bound, "com.android.vending")).isEmpty())
        assertTrue(AppBehaviorRules.evaluate(facts(risky, bound, null, system = true)).isEmpty())
    }

    @Test fun sideloadedBankingTrojanCombinationIsHigh() {
        val r = AppBehaviorRules.evaluate(facts(setOf("SYSTEM_ALERT_WINDOW"), setOf("BIND_ACCESSIBILITY_SERVICE")))
        assertEquals(AppBehaviorRules.Level.HIGH, AppBehaviorRules.worst(r))
        assertEquals("A11Y_OVERLAY_SMS", r.first().id)
    }

    @Test fun otpStealerCombinationIsHigh() {
        val r = AppBehaviorRules.evaluate(facts(setOf("RECEIVE_SMS"), setOf("BIND_NOTIFICATION_LISTENER_SERVICE")))
        assertTrue(r.any { it.id == "LISTENER_SMS" && it.level == AppBehaviorRules.Level.HIGH })
    }

    @Test fun ordinarySideloadedAppHasNoIndicators() {
        assertTrue(AppBehaviorRules.evaluate(facts(setOf("INTERNET", "CAMERA"), emptySet(), "com.google.android.packageinstaller")).isEmpty())
    }

    @Test fun lowSignalsStayLow() {
        val r = AppBehaviorRules.evaluate(facts(setOf("MANAGE_EXTERNAL_STORAGE")))
        assertEquals(AppBehaviorRules.Level.LOW, AppBehaviorRules.worst(r))
    }

    @Test fun keyIgnoresOrderAndSourceLabels() {
        assertEquals("sideload", AppBehaviorRules.source(facts(installer = null)))
        assertEquals("store", AppBehaviorRules.source(facts(installer = "com.android.vending")))
        assertEquals("system", AppBehaviorRules.source(facts(system = true)))
        val a = AppBehaviorRules.evaluate(facts(setOf("REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE")))
        assertEquals(AppBehaviorRules.key(a), AppBehaviorRules.key(a.reversed()))
    }
}
