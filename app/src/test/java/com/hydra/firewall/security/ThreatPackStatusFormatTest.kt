package com.hydra.firewall.security

import com.hydra.firewall.security.ThreatPackStatusFormat.Health
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatPackStatusFormatTest {
    private val day = 24L * 60 * 60 * 1000
    private val now = 1_800_000_000_000L

    private fun status(enabled: Boolean = true, generated: Long = now - 2 * day, expires: Long = now + 10 * day) = ThreatSignatureStatus(
        enabled = enabled, packVersion = "2026.10.25.0500", generatedAt = generated, expiresAt = expires,
        sha256Count = 0, domainCount = 1200, ipCount = 300, urlCount = 0, yaraRuleCount = 6,
        sourceSummary = listOf("Feodo Tracker"), lastUpdateError = null
    )

    @Test fun disabledWins() = assertEquals(Health.DISABLED, ThreatPackStatusFormat.summarize(status(enabled = false), true, now - day, now).health)

    @Test fun expiredPackIsReportedAsIgnored() {
        val s = ThreatPackStatusFormat.summarize(status(expires = now - day), true, now - 5 * day, now)
        assertEquals(Health.EXPIRED, s.health)
        assertTrue(s.headlineEs.contains("venció") && s.headlineEn.contains("expired"))
    }

    @Test fun expiringSoonShowsDaysLeft() {
        val s = ThreatPackStatusFormat.summarize(status(expires = now + 2 * day + 1000), true, now - day, now)
        assertEquals(Health.EXPIRING_SOON, s.health)
        assertEquals(2L, s.daysToExpire)
    }

    @Test fun bundledOnlyExplainsWhyThereAreNoUpdates() {
        val noFeed = ThreatPackStatusFormat.summarize(status(expires = 0), false, 0, now)
        assertEquals(Health.BUNDLED_ONLY, noFeed.health)
        assertTrue(noFeed.headlineEs.contains("no está configurada"))
        val feed = ThreatPackStatusFormat.summarize(status(expires = 0), true, 0, now)
        assertTrue(feed.headlineEs.contains("todavía no se descargó"))
    }

    @Test fun healthyPackAndCounts() {
        val s = ThreatPackStatusFormat.summarize(status(), true, now - day, now)
        assertEquals(Health.OK, s.health)
        assertEquals(1500, s.indicatorCount)           // dominios + IPs (YARA no cuenta como indicador)
        assertEquals(2L, s.ageDays)
    }

    @Test fun nonExpiringPackHasNoExpiryNumber() = assertNull(ThreatPackStatusFormat.summarize(status(expires = 0), true, now - day, now).daysToExpire)

    @Test fun hostOfShowsOnlyTheHostAndRejectsNonHttps() {
        assertEquals("raw.githubusercontent.com", ThreatPackStatusFormat.hostOf("https://raw.githubusercontent.com/u/r/threat-pack/p.json?token=SECRET"))
        assertEquals("example.org", ThreatPackStatusFormat.hostOf("https://user:pw@example.org:8443/x"))
        assertNull(ThreatPackStatusFormat.hostOf("http://example.org/x"))
        assertNull(ThreatPackStatusFormat.hostOf(""))
        assertNull(ThreatPackStatusFormat.hostOf("https:///x"))
    }

    @Test fun friendlyErrorsAreReadableAndUnknownOnesKeepTheCode() {
        assertTrue(ThreatPackStatusFormat.friendlyError("signature_invalid", false)!!.contains("firma inválida"))
        assertTrue(ThreatPackStatusFormat.friendlyError("http_404", true)!!.contains("404"))
        assertTrue(ThreatPackStatusFormat.friendlyError("boom", false)!!.contains("boom"))
        assertNull(ThreatPackStatusFormat.friendlyError("  ", false))
        assertNull(ThreatPackStatusFormat.friendlyError(null, true))
    }

    @Test fun updateModeText() {
        assertTrue(ThreatPackStatusFormat.updateModeText(false, null, false).contains("desactivada"))
        assertTrue(ThreatPackStatusFormat.updateModeText(true, "example.org", true).contains("example.org"))
    }
}
