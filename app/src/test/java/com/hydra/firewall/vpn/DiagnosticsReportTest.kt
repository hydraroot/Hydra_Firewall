package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DiagnosticsReportTest {
    @Test fun packageNamesAreRedactedFromEventTitles() {
        val t = DiagnosticsReport.redactTitle("Security baseline changed: com.bank.app")
        assertFalse(t.contains("com.bank.app"))
        assertEquals("Security baseline changed: <redacted>", t)
    }

    @Test fun hostsAndIpsAreRedacted() {
        assertEquals("Blocked <redacted> via <redacted>", DiagnosticsReport.redactTitle("Blocked ads.tracker.example.com via 10.1.2.3"))
    }

    @Test fun plainTitlesAreUntouched() {
        assertEquals("Too many active connections", DiagnosticsReport.redactTitle("Too many active connections"))
        assertEquals("QUIC domain blocked", DiagnosticsReport.redactTitle("QUIC domain blocked"))
    }
}
