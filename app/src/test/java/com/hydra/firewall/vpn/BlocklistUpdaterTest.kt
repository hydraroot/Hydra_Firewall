package com.hydra.firewall.vpn

import org.junit.Assert.assertFalse
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
}
