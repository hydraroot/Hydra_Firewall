package com.hydra.firewall.security

import org.junit.Assert.*
import org.junit.Test

class AppThreatScannerTest {
    private fun m(name: String) = ThreatSignatureMatch(ThreatSignatureMatch.Kind.YARA, name, null, "src", Severity.MEDIUM, 50, "d")
    private fun f(pkg: String, vararg names: String) = AppThreatScanner.Finding(pkg, "L", names.map(::m), 1L)

    @Test fun ruleKeyIgnoresOrderButNotContent() {
        assertEquals(AppThreatScanner.ruleKey(f("a", "x", "y")), AppThreatScanner.ruleKey(f("a", "y", "x")))
        assertNotEquals(AppThreatScanner.ruleKey(f("a", "x")), AppThreatScanner.ruleKey(f("a", "x", "z")))
    }

    @Test fun findingsRoundTrip() {
        val list = listOf(f("a", "x", "y"), f("b", "z"))
        val back = AppThreatScanner.decodeFindings(AppThreatScanner.encodeFindings(list))
        assertEquals(list.map { it.packageName }, back.map { it.packageName })
        assertEquals(list.map { AppThreatScanner.ruleKey(it) }, back.map { AppThreatScanner.ruleKey(it) })
    }

    @Test fun notifiesOnlyWhenRulesChange() {
        assertTrue(AppThreatScanner.isNewFinding(null, f("a", "x")))
        assertFalse(AppThreatScanner.isNewFinding(f("a", "x"), f("a", "x")))
        assertTrue(AppThreatScanner.isNewFinding(f("a", "x"), f("a", "x", "y")))
    }
}
