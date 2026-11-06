package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PauseManagerTest {
    @Test fun remainingIsZeroWithoutPauseOrAfterEnd() {
        assertEquals(0L, PauseManager.remaining(0L, 1000L))
        assertEquals(0L, PauseManager.remaining(500L, 1000L))
        assertEquals(500L, PauseManager.remaining(1500L, 1000L))
    }

    @Test fun formatRoundsUpToWholeSeconds() {
        assertEquals("15:00", PauseManager.formatRemaining(900_000L))
        assertEquals("0:01", PauseManager.formatRemaining(1L))
        assertEquals("1:00", PauseManager.formatRemaining(60_000L))
        assertEquals("0:00", PauseManager.formatRemaining(-5L))
    }
}

class WeeklyStatsTest {
    private fun day(k: String, a: Long, b: Long, ads: Long, vararg apps: Pair<String, Long>) =
        WeeklyStats.Day(k, a, b, ads, apps.toMap().toMutableMap())

    @Test fun summarizeOnlyCountsKeysInWindowAndRanksApps() {
        val days = listOf(
            day("20260101", 10, 5, 2, "a" to 3L, "b" to 2L),
            day("20260102", 1, 4, 1, "b" to 4L, "c" to 1L),
            day("20250101", 99, 99, 99, "z" to 99L)
        )
        val s = WeeklyStats.summarize(days, setOf("20260101", "20260102"))
        assertEquals(11L, s.allowed); assertEquals(9L, s.blocked); assertEquals(3L, s.ads)
        assertEquals(listOf("b" to 6L, "a" to 3L, "c" to 1L), s.top)
    }

    @Test fun emptyWhenNothingCounted() {
        assertTrue(WeeklyStats.summarize(emptyList(), setOf("20260101")).isEmpty)
    }

    @Test fun encodeDecodeRoundTrip() {
        val d = day("20260101", 1, 2, 3, "a" to 4L)
        val back = WeeklyStats.decode(WeeklyStats.encode(listOf(d))).single()
        assertEquals(d.key, back.key); assertEquals(2L, back.blocked); assertEquals(mapOf("a" to 4L), back.perApp)
    }

    @Test fun windowHasSevenDistinctDays() {
        assertEquals(7, WeeklyStats.windowKeys(System.currentTimeMillis()).size)
    }
}

class AppNamesTest {
    @Test fun wellKnownSystemUidsGetAName() {
        assertEquals("Sistema Android (1000)", AppNames.fallback(1000, false))
        assertEquals("Network daemon (netd) (1051)", AppNames.fallback(1051, true))
    }

    @Test fun unknownUidsKeepTheNumberButSayWhatTheyAre() {
        assertEquals("Proceso del sistema (UID 1099)", AppNames.fallback(1099, false))
        assertEquals("Unknown or uninstalled app (UID 10234)", AppNames.fallback(10234, true))
        assertEquals("?", AppNames.fallback(-1, false))
    }
}
