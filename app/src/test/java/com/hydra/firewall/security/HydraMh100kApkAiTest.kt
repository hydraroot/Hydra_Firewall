package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class HydraMh100kApkAiTest {
    @Test
    fun loadsProductionModelAndHonorsAbsenceMode() {
        val model = javaClass.classLoader!!.getResourceAsStream("hydra_apk_ai_mh100k_v2.bin")!!.readBytes()
        HydraMh100kApkAi.loadModelForTest(model)

        val empty = HydraMh100kApkAi.score(LongArray(0))!!
        assertEquals("hydra-apk-ai-mh100k-v2", empty.modelVersion)
        assertEquals(2048, empty.modelFeatureCount)
        assertEquals(1139, empty.matchedFeatures)
        assertEquals(99, empty.score)

        // First binary feature is an absence-mode feature. Supplying its hash
        // therefore removes one activated feature and changes the logit.
        val firstHash = 0x001d1e73e647697dL
        val withFirst = HydraMh100kApkAi.score(longArrayOf(firstHash))!!
        assertEquals(1138, withFirst.matchedFeatures)
        assertNotEquals(empty.rawLogit, withFirst.rawLogit)
    }

    @Test
    fun extractorRecognizesSelectedPermissionHash() {
        val model = javaClass.classLoader!!.getResourceAsStream("hydra_apk_ai_mh100k_v2.bin")!!.readBytes()
        HydraMh100kApkAi.loadModelForTest(model)
        val temp = Files.createTempFile("hydra-mh100k", ".apk").toFile()
        try {
            ZipOutputStream(temp.outputStream()).use { it.putNextEntry(ZipEntry("AndroidManifest.xml")) }
            val result = Mh100kStaticFeatureExtractor().extract(
                temp,
                permissions = listOf("android.permission.WRITE_SETTINGS")
            )
            assertTrue(result.presentFeatureHashes.isNotEmpty())
            assertTrue(result.permissionFeaturesObserved >= 1)
        } finally {
            temp.delete()
        }
    }

    @Test
    fun suspicionLabelDoesNotPresentMidScoresAsAlarms() {
        assertTrue(HydraMh100kApkAi.suspicionLabel(60, true).startsWith("Weak hint"))
        assertTrue(HydraMh100kApkAi.suspicionLabel(92, true).startsWith("High suspicion"))
        assertTrue(HydraMh100kApkAi.suspicionLabel(97, true).startsWith("Very high"))
        assertTrue(HydraMh100kApkAi.suspicionLabel(10, true).startsWith("Low"))
    }
}
