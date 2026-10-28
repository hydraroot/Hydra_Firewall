package com.hydra.firewall.vpn

import com.hydra.firewall.vpn.AppUsageInsights.Flag
import com.hydra.firewall.vpn.AppUsageInsights.Input
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUsageInsightsTest {
    private val mb = 1024L * 1024L
    private fun app(k: String, tx: Long = 0, rx: Long = 0, c: Long = 0, b: Long = 0) = Input(k, k, 10000, tx, rx, c, b)

    @Test
    fun ranksByTotalBytesAndComputesShare() {
        val r = AppUsageInsights.rank(listOf(app("a", rx = 10 * mb), app("b", rx = 30 * mb), app("c", rx = 60 * mb)))
        assertEquals(listOf("c", "b", "a"), r.map { it.key })
        assertEquals(listOf(60, 30, 10), r.map { it.sharePercent })
    }

    @Test
    fun appsWithNoActivityAreDropped() {
        val r = AppUsageInsights.rank(listOf(app("quiet"), app("busy", rx = 1)))
        assertEquals(listOf("busy"), r.map { it.key })
    }

    @Test
    fun heavyDataNeedsBothShareAndAbsoluteSize() {
        val big = AppUsageInsights.rank(listOf(app("hog", rx = 90 * mb), app("other", rx = 10 * mb))).first()
        assertTrue(Flag.HEAVY_DATA in big.flags)
        // 100 % del tráfico, pero sólo 100 KB: no es "mucho"
        val tiny = AppUsageInsights.rank(listOf(app("tiny", rx = 100 * 1024))).first()
        assertFalse(Flag.HEAVY_DATA in tiny.flags)
    }

    @Test
    fun uploadHeavyFlagsUploadsFarAboveDownloads() {
        assertTrue(Flag.UPLOAD_HEAVY in AppUsageInsights.rank(listOf(app("u", tx = 20 * mb, rx = 2 * mb))).first().flags)
        assertFalse(Flag.UPLOAD_HEAVY in AppUsageInsights.rank(listOf(app("u", tx = 20 * mb, rx = 15 * mb))).first().flags)
        assertFalse("subida chica no cuenta", Flag.UPLOAD_HEAVY in AppUsageInsights.rank(listOf(app("u", tx = 1 * mb, rx = 0))).first().flags)
    }

    @Test
    fun chattyAndMostlyBlocked() {
        val r = AppUsageInsights.rank(listOf(app("chat", c = 250, rx = 1), app("fw", c = 3, b = 40)))
        assertTrue(Flag.CHATTY in r.first { it.key == "chat" }.flags)
        assertTrue(Flag.MOSTLY_BLOCKED in r.first { it.key == "fw" }.flags)
        assertFalse(Flag.MOSTLY_BLOCKED in AppUsageInsights.rank(listOf(app("ok", c = 100, b = 25))).first().flags)
    }

    @Test
    fun topNIsHonouredAndNegativeValuesAreClamped() {
        val many = (1..30).map { app("p$it", rx = it * 1000L) }
        assertEquals(10, AppUsageInsights.rank(many).size)
        val r = AppUsageInsights.rank(listOf(app("neg", tx = -5, rx = 100)), 3).first()
        assertEquals(100, r.totalBytes)
    }

    @Test
    fun formatBytesUsesSensibleUnits() {
        assertEquals("0 B", AppUsageInsights.formatBytes(-4))
        assertEquals("512 B", AppUsageInsights.formatBytes(512))
        assertEquals("1.5 KB", AppUsageInsights.formatBytes(1536))
        assertEquals("2.0 MB", AppUsageInsights.formatBytes(2 * mb))
        assertEquals("1.50 GB", AppUsageInsights.formatBytes(1536 * mb))
    }

    // --- Libro diario ---------------------------------------------------------------------------

    @Test
    fun ledgerAccumulatesSumsAndRoundTrips() {
        val l = DailyUsageLedger()
        l.add("2026-10-25", "com.a", 100); l.add("2026-10-25", "com.a", 50); l.add("2026-10-26", "com.a", 5); l.add("2026-10-26", "uid:10001", 7)
        assertEquals(150L, l.day("2026-10-25")["com.a"])
        assertEquals(mapOf("com.a" to 155L, "uid:10001" to 7L), l.sum(listOf("2026-10-25", "2026-10-26")))
        val back = DailyUsageLedger.parse(l.serialize())
        assertEquals(l.sum(l.dayKeys()), back.sum(back.dayKeys()))
    }

    @Test
    fun ledgerKeepsOnlyTheLastNDays() {
        val l = DailyUsageLedger(keepDays = 3)
        for (d in 1..6) l.add("2026-10-0$d", "k", 1)
        assertEquals(listOf("2026-10-04", "2026-10-05", "2026-10-06"), l.dayKeys())
    }

    @Test
    fun ledgerCapsKeysPerDayButStillAccumulatesExistingOnes() {
        val l = DailyUsageLedger(maxKeysPerDay = 2)
        l.add("2026-10-25", "a", 1); l.add("2026-10-25", "b", 1); l.add("2026-10-25", "c", 1); l.add("2026-10-25", "a", 4)
        assertEquals(mapOf("a" to 5L, "b" to 1L), l.day("2026-10-25"))
    }

    @Test
    fun ledgerRejectsGarbageOnParseAndAdd() {
        val l = DailyUsageLedger.parse("hola\n2026-10-25\tcom.ok\t10\nxx\tcom.x\t1\n2026-10-25\tbad key\t1\n2026-10-25\tcom.neg\t-3\n2026-10-25\tcom.nan\tabc\n")
        assertEquals(mapOf("com.ok" to 10L), l.day("2026-10-25"))
        assertTrue(DailyUsageLedger.parse(null).dayKeys().isEmpty())
    }
}
