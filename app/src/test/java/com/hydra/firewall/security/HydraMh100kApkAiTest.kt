package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private typealias VerdictLevel = HydraMh100kApkAi.Verdict.Level

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
    fun modelWithNonFiniteWeightIsRejected() {
        val model = javaClass.classLoader!!.getResourceAsStream("hydra_apk_ai_mh100k_v2.bin")!!.readBytes()
        // Primer entry: hash(8) + weight float32 en offset 20 + 8 = 28 -> NaN (0x7FC00000 little-endian).
        model[28] = 0x00; model[29] = 0x00; model[30] = 0xC0.toByte(); model[31] = 0x7F
        val ok = runCatching { HydraMh100kApkAi.loadModelForTest(model) }.isFailure
        assertTrue(ok)
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
    fun intentSuffixMatchesOldRegexAndStaysFastOnHugeStrings() {
        val old = Regex("""([A-Z][A-Z0-9_]{2,})$""")
        val samples = listOf(
            "android.intent.action.BOOT_COMPLETED", "ABC", "AB", "aBCD", "x_ABC9", "1AB", "A_9z", "", "ab_CD_E1", "_ABC", "9ABC"
        )
        for (sample in samples) {
            assertEquals(sample, old.find(sample)?.groupValues?.get(1), Mh100kStaticFeatureExtractor.intentSuffix(sample))
        }
        // The old regex needed ~47 s for 100,000 characters; the linear version must be instant.
        val huge = "A".repeat(2_000_000) + "x"
        val started = System.currentTimeMillis()
        assertEquals(null, Mh100kStaticFeatureExtractor.intentSuffix(huge))
        assertTrue(System.currentTimeMillis() - started < 1_000L)
    }

    @Test
    fun verdictGoesOneDirectionAndNeedsEnoughCodeSeen() {
        // Enough code seen: the higher the score, the worse the verdict.
        assertEquals(VerdictLevel.NORMAL, HydraMh100kApkAi.verdict(0, 5000, 2, false, true).level)
        assertEquals(VerdictLevel.NORMAL, HydraMh100kApkAi.verdict(49, 5000, 2, false, true).level)
        assertEquals(VerdictLevel.DOUBTFUL, HydraMh100kApkAi.verdict(50, 5000, 2, false, true).level)
        assertEquals(VerdictLevel.DOUBTFUL, HydraMh100kApkAi.verdict(89, 5000, 2, false, true).level)
        assertEquals(VerdictLevel.SUSPICIOUS, HydraMh100kApkAi.verdict(90, 5000, 2, false, true).level)
        assertEquals(VerdictLevel.SUSPICIOUS, HydraMh100kApkAi.verdict(100, 5000, 2, false, true).level)
        // Incomplete analysis or almost no code seen: no verdict, whatever the score says.
        assertEquals(VerdictLevel.INCONCLUSIVE, HydraMh100kApkAi.verdict(95, 5000, 2, true, true).level)
        assertEquals(VerdictLevel.INCONCLUSIVE, HydraMh100kApkAi.verdict(5, 5000, 0, false, true).level)
        assertEquals(VerdictLevel.INCONCLUSIVE, HydraMh100kApkAi.verdict(5, 100, 1, false, true).level)
    }
}
