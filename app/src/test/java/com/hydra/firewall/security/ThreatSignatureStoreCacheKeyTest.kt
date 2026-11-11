package com.hydra.firewall.security

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class ThreatSignatureStoreCacheKeyTest {
    @Test
    fun cacheIdentityIncludesPackRevisionAndAllApkFiles() {
        val base = File.createTempFile("hydra-cache-base", ".apk")
        val split = File.createTempFile("hydra-cache-split", ".apk")
        try {
            base.writeText("base-one")
            split.writeText("split-one")
            val initial = ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 100L)

            assertEquals(initial, ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 100L))
            assertNotEquals(initial, ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-2", 100L))
            assertNotEquals(initial, ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 101L))

            base.writeText("base-two-content")
            assertNotEquals(initial, ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 100L))

            val afterBaseChange = ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 100L)
            split.writeText("split-two-content")
            assertNotEquals(afterBaseChange, ThreatSignatureStore.apkScanCacheKey(base, listOf(split), "pack-1", 100L))
        } finally {
            base.delete()
            split.delete()
        }
    }
}
