package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionHardeningTest {
    @Test fun riskScoreIsBounded() {
        val r = SecurityRiskEngine.evaluate(
            permissions = listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO", "android.permission.SYSTEM_ALERT_WINDOW"),
            exportedComponents = 20, accessibilityServices = 2, deviceAdminReceivers = 1,
            hasOverlayPermission = true, canInstallPackages = true, debuggable = true, nativeLibraries = 4, dexFiles = 8
        )
        assertTrue(r.score in 0..100)
        assertEquals(RiskLevel.CRITICAL, r.level)
    }
}
