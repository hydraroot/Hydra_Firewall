package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BlocklistUpdaterTest {
    private val installed = mapOf("stevenblack" to "26 Oct 2026 03:00:00 (UTC)", "hagezi_pro_mini" to "2026-10-26 02:00")

    @Test fun sameDatesMeansUpToDate() {
        assertFalse(BlocklistUpdater.hasNewer(installed, installed))
    }

    @Test fun oneSourceNewerMeansUpdate() {
        val remote = installed + ("stevenblack" to "27 Oct 2026 03:00:00 (UTC)")
        assertTrue(BlocklistUpdater.hasNewer(installed, remote))
    }

    @Test fun noSavedMetadataOffersUpdateOnce() {
        assertTrue(BlocklistUpdater.hasNewer(emptyMap(), installed))
    }

    @Test fun nothingCheckedIsNotNewer() {
        assertFalse(BlocklistUpdater.hasNewer(installed, emptyMap()))
    }

    @Test fun subsetOfSourcesStillComparesExactly() {
        assertFalse(BlocklistUpdater.hasNewer(installed, mapOf("stevenblack" to "26 Oct 2026 03:00:00 (UTC)")))
    }

    @Test fun autoUpdateRunsOnFirstCheck() {
        assertTrue(BlocklistUpdater.shouldRunAutoUpdate(0L, 1_000L, force = false))
    }

    @Test fun autoUpdateWaitsUntilTwentyFourHoursHaveElapsed() {
        val day = 24L * 60L * 60L * 1000L
        assertFalse(BlocklistUpdater.shouldRunAutoUpdate(10_000L, 10_000L + day - 1L, force = false))
        assertTrue(BlocklistUpdater.shouldRunAutoUpdate(10_000L, 10_000L + day, force = false))
    }

    @Test fun forcedAutoUpdateIgnoresTheInterval() {
        assertTrue(BlocklistUpdater.shouldRunAutoUpdate(10_000L, 10_001L, force = true))
    }

    @Test fun clockMovingBackwardsDoesNotSuppressAutoUpdate() {
        assertTrue(BlocklistUpdater.shouldRunAutoUpdate(20_000L, 10_000L, force = false))
    }

    @Test fun updateAndDnsHostsCanNeverBeBlockedByADownloadedList() {
        assertNull(BlocklistUpdater.parseDomain("0.0.0.0 github.com"))
        assertNull(BlocklistUpdater.parseDomain("0.0.0.0 raw.githubusercontent.com"))
        assertNull(BlocklistUpdater.parseDomain("||api.github.com^"))
        assertNull(BlocklistUpdater.parseDomain("*.cloudflare-dns.com"))
        assertNull(BlocklistUpdater.parseDomain("dns.google"))
    }

    @Test fun ordinaryTrackerDomainsStillParse() {
        assertEquals("ads.example.com", BlocklistUpdater.parseDomain("0.0.0.0 ads.example.com"))
        assertEquals("tracker.example.net", BlocklistUpdater.parseDomain("||tracker.example.net^"))
        assertEquals("evilgithub.com", BlocklistUpdater.parseDomain("0.0.0.0 evilgithub.com"))
        assertTrue(BlocklistUpdater.isProtectedDomain("objects.githubusercontent.com"))
        assertFalse(BlocklistUpdater.isProtectedDomain("notgithub.com"))
    }
}
