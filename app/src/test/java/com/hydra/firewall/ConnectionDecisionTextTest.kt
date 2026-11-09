package com.hydra.firewall

import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionDecisionTextTest {
    @Test
    fun explainsAdTrackerBlockPreciselyInSpanishAndEnglish() {
        assertTrue(ConnectionDecisionText.explanation("AD_TRACKER_BLOCKLIST", true, false).contains("publicidad y rastreadores"))
        assertTrue(ConnectionDecisionText.explanation("AD_TRACKER_BLOCKLIST", true, true).contains("advertising and tracker"))
    }

    @Test
    fun explainsRecordedAppRuleAccordingToDecision() {
        val blocked = ConnectionDecisionText.explanation("EXPLICIT_APP_RULE", true, false)
        val allowed = ConnectionDecisionText.explanation("EXPLICIT_APP_RULE", false, false)
        assertTrue(blocked.contains("bloquea la red"))
        assertTrue(allowed.contains("permite la red"))
    }

    @Test
    fun neverPretendsLegacyRecordsHaveAnExactCause() {
        assertTrue(ConnectionDecisionText.explanation(null, true, false).contains("no conserva la regla exacta"))
        assertTrue(ConnectionDecisionText.explanation(null, false, true).contains("exact allow rule was not stored"))
    }

    @Test
    fun explainsThreatAndIpRules() {
        assertTrue(ConnectionDecisionText.explanation("THREAT_DOMAIN", true, false).contains("inteligencia de amenazas"))
        assertTrue(ConnectionDecisionText.explanation("USER_IP_BLOCK", true, true).contains("IP block rules"))
    }
}
