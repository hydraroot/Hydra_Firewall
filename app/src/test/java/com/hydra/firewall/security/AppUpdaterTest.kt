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

class AppUpdaterMoreTest {
    @Test fun parseVersionHandlesPrefixesAndGarbage() {
        assertEquals(listOf(2, 2, 0), AppUpdater.parseVersion("v2.2.0"))
        assertEquals(listOf(2, 2, 0), AppUpdater.parseVersion("Hydra-Firewall-2.2.0-rc"))
        assertNull(AppUpdater.parseVersion("latest"))
        assertNull(AppUpdater.parseVersion("2.2"))
    }

    @Test fun newerIsNotFooledByStringOrder() {
        assertTrue(AppUpdater.isNewer("v2.10.0", "2.9.0"))
        assertFalse(AppUpdater.isNewer("v2.9.0", "2.10.0"))
    }

    @Test fun picksSha256AssetAndKeepsSizeAndNotes() {
        val json = """[{"tag_name":"v2.2.0","body":"notes","assets":[
          {"name":"Hydra-Firewall-v2.2.0.apk","browser_download_url":"https://e/h.apk","size":123},
          {"name":"Hydra-Firewall-v2.2.0.apk.sha256","browser_download_url":"https://e/h.apk.sha256"}]}]"""
        val r = AppUpdater.parseReleases(json)!!
        assertEquals(123L, r.sizeBytes)
        assertEquals("https://e/h.apk.sha256", r.sha256Url)
        assertNull(r.sha256)
        assertEquals("notes", r.notes)
    }

    @Test fun ignoresReleaseWithoutApkAndBadDigestLength() {
        val json = """[{"tag_name":"v3.0.0","assets":[{"name":"a.apk","browser_download_url":"https://e/a.apk","digest":"sha256:abc"}]}]"""
        val r = AppUpdater.parseReleases(json)!!
        assertNull(r.sha256)
        assertNull(AppUpdater.parseReleases("[]"))
    }

    @Test fun signatureRule() {
        assertTrue(AppUpdater.signaturesCompatible(setOf("a"), setOf("a")))
        assertTrue(AppUpdater.signaturesCompatible(setOf("a", "b"), setOf("b")))
        assertTrue(AppUpdater.signaturesCompatible(setOf("a"), emptySet()))
        assertFalse(AppUpdater.signaturesCompatible(setOf("a"), setOf("b")))
        assertFalse(AppUpdater.signaturesCompatible(emptySet(), setOf("b")))
    }

    @Test fun sha256HexMatchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", AppUpdater.sha256Hex("abc".toByteArray()))
    }
}

class AppUpdaterProgressTest {
    @Test fun fractionIsClampedAndNullWhenSizeUnknown() {
        assertEquals(0.5f, AppUpdater.fraction(50, 100)!!, 0.0001f)
        assertEquals(1f, AppUpdater.fraction(150, 100)!!, 0.0001f)
        assertEquals(0f, AppUpdater.fraction(0, 100)!!, 0.0001f)
        assertNull(AppUpdater.fraction(10, 0))
        assertNull(AppUpdater.fraction(10, -1))
    }

    @Test fun ignoresPrereleases() {
        val json = """[
          {"tag_name":"v9.9.9","prerelease":true,"assets":[{"name":"a.apk","browser_download_url":"https://e/a.apk"}]},
          {"tag_name":"v1.2.4","assets":[{"name":"b.apk","browser_download_url":"https://e/b.apk"}]}
        ]"""
        assertEquals("1.2.4", AppUpdater.parseReleases(json)!!.version)
    }

    @Test fun absurdVersionNumbersAreRejectedInsteadOfCrashing() {
        assertNull(AppUpdater.parseVersion("v99999999999.0.0"))
        assertNull(AppUpdater.parseVersion("1234567.1.1"))
        assertEquals(listOf(3, 4, 5), AppUpdater.parseVersion("v3.4.5"))
        assertFalse(AppUpdater.isNewer("v99999999999.0.0", "1.0.0"))
    }
}
