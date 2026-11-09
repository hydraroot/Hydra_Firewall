package com.hydra.firewall.security

import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityRiskEngineTest {
    @Test fun cleartextIncreasesRisk() {
        val r = SecurityRiskEngine.evaluate(
            permissions = emptyList(),
            exportedComponents = 0, accessibilityServices = 0, deviceAdminReceivers = 0,
            hasOverlayPermission = false, canInstallPackages = false, debuggable = false,
            nativeLibraries = 0, dexFiles = 1,
            exportedUnprotectedComponents = 0,
            cleartextTrafficAllowed = true, hasNetworkSecurityConfig = false
        )
        assertTrue(r.indicators.any { it.code == "CLEARTEXT" })
        assertTrue(r.score >= 8)
    }

    @Test fun exportedUnprotectedIsReported() {
        val r = SecurityRiskEngine.evaluate(emptyList(),2,0,0,false,false,false,0,1,2)
        assertTrue(r.indicators.any { it.code == "EXPORTED_UNPROTECTED" })
    }
}
