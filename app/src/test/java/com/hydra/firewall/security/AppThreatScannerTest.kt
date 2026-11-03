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

class AppThreatScannerReasonTest {
    private fun m(kind: ThreatSignatureMatch.Kind, name: String) = ThreatSignatureMatch(kind, name, null, "src", Severity.HIGH, 90, "d")

    @Test fun plainReasonDiffersForHashAndPattern() {
        val hash = AppThreatScanner.Finding("a", "A", listOf(m(ThreatSignatureMatch.Kind.SHA256, "Evil")), 1L)
        val yara = AppThreatScanner.Finding("a", "A", listOf(m(ThreatSignatureMatch.Kind.YARA, "Pat")), 1L)
        assertTrue(AppThreatScanner.plainReason(hash, true).contains("identical"))
        assertTrue(AppThreatScanner.plainReason(yara, true).contains("false positive"))
        assertTrue(AppThreatScanner.plainReason(hash, false).contains("idéntico"))
    }
}

class AppThreatScannerIgnoreTest {
    private fun ind(id: String, lvl: AppBehaviorRules.Level) = AppBehaviorRules.Indicator(id, lvl, "es $id", "en $id")

    @Test fun signerChangedOnlyWhenBothKnownAndDifferent() {
        assertFalse(AppThreatScanner.signerChanged("aa", "aa"))
        assertTrue(AppThreatScanner.signerChanged("aa", "bb"))
        assertFalse(AppThreatScanner.signerChanged(null, "bb"))
        assertFalse(AppThreatScanner.signerChanged("aa", null))
    }

    @Test fun behaviorRoundTripKeepsIndicatorsAndLevels() {
        val list = listOf(
            AppThreatScanner.BehaviorFinding("p.a", "A", listOf(ind("X", AppBehaviorRules.Level.HIGH), ind("Y", AppBehaviorRules.Level.LOW)), 5L),
            AppThreatScanner.BehaviorFinding("p.b", "B", listOf(ind("Z", AppBehaviorRules.Level.MEDIUM)), 6L)
        )
        val back = AppThreatScanner.decodeBehavior(AppThreatScanner.encodeBehavior(list))
        assertEquals(list, back)
    }

    @Test fun decodeBehaviorSurvivesGarbageAndDropsEmptyIndicators() {
        assertTrue(AppThreatScanner.decodeBehavior("not json").isEmpty())
        assertTrue(AppThreatScanner.decodeBehavior("""[{"pkg":"p","label":"L","time":1,"ind":[]}]""").isEmpty())
    }

    @Test fun ignoreDateIsPreservedByCopy() {
        val m = ThreatSignatureMatch(ThreatSignatureMatch.Kind.YARA, "x", null, "s", Severity.MEDIUM, 50, "d")
        val f = AppThreatScanner.Finding("a", "A", listOf(m), 1L)
        val ignored = f.copy(time = 999L)
        assertEquals(999L, AppThreatScanner.decodeFindings(AppThreatScanner.encodeFindings(listOf(ignored))).first().time)
        assertEquals(AppThreatScanner.ruleKey(f), AppThreatScanner.ruleKey(ignored))
    }
}

class AppThreatScannerSuppressTest {
    private fun f(kind: ThreatSignatureMatch.Kind) = AppThreatScanner.Finding("a", "A", listOf(ThreatSignatureMatch(kind, "n", null, "s", Severity.MEDIUM, 50, "d")), 1L)

    @Test fun patternOnlyIsSuppressedForStoreAndSystemApps() {
        assertTrue(AppThreatScanner.suppressPatternOnly(f(ThreatSignatureMatch.Kind.YARA), "store"))
        assertTrue(AppThreatScanner.suppressPatternOnly(f(ThreatSignatureMatch.Kind.YARA), "system"))
        assertFalse(AppThreatScanner.suppressPatternOnly(f(ThreatSignatureMatch.Kind.YARA), "sideload"))
    }

    @Test fun knownMalwareHashIsNeverSuppressed() {
        assertFalse(AppThreatScanner.suppressPatternOnly(f(ThreatSignatureMatch.Kind.SHA256), "store"))
        assertFalse(AppThreatScanner.suppressPatternOnly(f(ThreatSignatureMatch.Kind.SHA256), "system"))
    }
}
