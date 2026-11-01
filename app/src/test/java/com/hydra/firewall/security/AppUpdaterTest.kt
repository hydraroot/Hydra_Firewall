package com.hydra.firewall.security

import org.junit.Assert.*
import org.junit.Test

class AppUpdaterTest {
    @Test fun versionOrdering() {
        assertTrue(AppUpdater.isNewer("v1.2.4", "1.2.3"))
        assertTrue(AppUpdater.isNewer("v1.3.0", "1.2.9"))
        assertTrue(AppUpdater.isNewer("2.0.0", "1.9.9"))
        assertFalse(AppUpdater.isNewer("v1.2.3", "1.2.3"))
        assertFalse(AppUpdater.isNewer("v1.2.2", "1.2.3"))
        assertFalse(AppUpdater.isNewer("latest", "1.2.3"))
    }

    @Test fun picksNewestReleaseWithApkAndIgnoresDrafts() {
        val h = "a".repeat(64)
        val json = """[
          {"tag_name":"v1.2.5","draft":true,"assets":[{"name":"x.apk","browser_download_url":"https://e/x.apk"}]},
          {"tag_name":"v1.2.4","assets":[{"name":"Hydra-Firewall-v1.2.4.apk","browser_download_url":"https://e/h.apk","size":10,"digest":"sha256:$h"}]},
          {"tag_name":"v1.2.3","assets":[{"name":"Hydra-Firewall-v1.2.3.apk","browser_download_url":"https://e/o.apk"}]},
          {"tag_name":"v1.2.6","assets":[{"name":"notes.txt","browser_download_url":"https://e/n.txt"}]}
        ]"""
        val r = AppUpdater.parseReleases(json)!!
        assertEquals("1.2.4", r.version)
        assertEquals(h, r.sha256)
    }

    @Test fun rejectsNonHttpsAssets() {
        val json = """[{"tag_name":"v9.0.0","assets":[{"name":"a.apk","browser_download_url":"http://e/a.apk"}]}]"""
        assertNull(AppUpdater.parseReleases(json))
    }
}
