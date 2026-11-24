package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class TcpStatsTest {
    @Before
    fun reset() = TcpStats.resetForTest()

    @Test
    fun countersIncrementIndependently() {
        TcpStats.inc(TcpStats.Counter.IDLE_TIMEOUT)
        TcpStats.inc(TcpStats.Counter.IDLE_TIMEOUT)
        TcpStats.inc(TcpStats.Counter.WINDOW_UPDATES)
        assertEquals(2L, TcpStats.get(TcpStats.Counter.IDLE_TIMEOUT))
        assertEquals(1L, TcpStats.get(TcpStats.Counter.WINDOW_UPDATES))
        assertEquals(0L, TcpStats.get(TcpStats.Counter.RETRANSMIT_LIMIT))
    }

    @Test
    fun peakOnlyGrows() {
        TcpStats.noteActive(5)
        TcpStats.noteActive(3)
        TcpStats.noteActive(9)
        TcpStats.noteActive(1)
        assertEquals(9, TcpStats.peakActiveSessions())
    }

    @Test
    fun reportListsEveryCounterAndPeak() {
        TcpStats.inc(TcpStats.Counter.RST_FROM_APP)
        val text = TcpStats.reportLines().joinToString("\n")
        TcpStats.Counter.values().forEach { assertTrue(it.label, text.contains("${it.label}=")) }
        assertTrue(text.contains("rst_from_app=1"))
        assertTrue(text.contains("peak_active_sessions="))
    }

    @Test
    fun reportNeverContainsAddressesOrPackageNames() {
        val text = TcpStats.reportLines().joinToString("\n")
        assertFalse(Regex("""\b\d{1,3}(?:\.\d{1,3}){3}\b""").containsMatchIn(text))
        assertFalse(Regex("""[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+){2,}""").containsMatchIn(text))
    }
}
