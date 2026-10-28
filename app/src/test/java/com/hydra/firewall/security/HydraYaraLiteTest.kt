package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class HydraYaraLiteTest {
    @Test
    fun parsesAndMatchesAndroidRule() {
        val source = """
            rule Hydra_Test_Android {
                meta:
                    family = "test-family"
                    severity = 85
                    description = "test rule"
                strings:
                    ${'$'}a = "RECEIVE_SMS" ascii
                    ${'$'}b = "SYSTEM_ALERT_WINDOW" ascii
                condition:
                    all of them
            }
        """.trimIndent()
        val rules = HydraYaraLite.parse(source)
        assertEquals(1, rules.size)
        assertEquals(2, rules.first().patterns.size)

        val file = Files.createTempFile("hydra-yara", ".apk").toFile()
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write("RECEIVE_SMS\u0000SYSTEM_ALERT_WINDOW".toByteArray())
                zip.closeEntry()
            }
            val matches = HydraYaraLite.scanApk(file, rules)
            assertEquals(1, matches.size)
            assertTrue(matches.first().name == "Hydra_Test_Android")
        } finally {
            file.delete()
        }
    }

    // ---- Regresiones agregadas (FIX158) ------------------------------------------------------

    private fun apk(vararg entries: Pair<String, ByteArray>): File {
        val f = Files.createTempFile("hydra-yara", ".apk").toFile()
        ZipOutputStream(f.outputStream()).use { z ->
            for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
        }
        return f
    }

    private fun utf16(s: String) = s.toByteArray(Charsets.UTF_16LE)

    private fun rule(name: String, severity: Int, condition: String, vararg literals: String): List<HydraYaraLite.Rule> {
        val strings = literals.mapIndexed { i, l -> "        ${'$'}s$i = \"$l\" ascii" }.joinToString("\n")
        return HydraYaraLite.parse(
            "rule $name {\n    meta:\n        severity = $severity\n    strings:\n$strings\n    condition:\n        $condition\n}"
        )
    }

    @Test
    fun matchesUtf16ManifestStrings() {
        val rules = rule("Utf16", 60, "2 of them", "android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW")
        val f = apk("AndroidManifest.xml" to (utf16("android.permission.READ_SMS") + utf16("android.permission.SYSTEM_ALERT_WINDOW")))
        try { assertEquals(1, HydraYaraLite.scanApk(f, rules).size) } finally { f.delete() }
    }

    @Test
    fun combinesPatternsAcrossManifestAndDex() {
        val rules = rule("Cross", 60, "all of them", "DexClassLoader", "android.permission.REQUEST_INSTALL_PACKAGES")
        val both = apk("classes.dex" to "DexClassLoader".toByteArray(), "AndroidManifest.xml" to utf16("android.permission.REQUEST_INSTALL_PACKAGES"))
        val onlyDex = apk("classes.dex" to "DexClassLoader".toByteArray())
        try {
            assertEquals(1, HydraYaraLite.scanApk(both, rules).size)
            assertEquals(0, HydraYaraLite.scanApk(onlyDex, rules).size)
        } finally { both.delete(); onlyDex.delete() }
    }

    @Test
    fun parsesCombinedModifiersAndHonoursWideOnly() {
        val combined = HydraYaraLite.parse(
            "rule T {\n meta:\n severity = 70\n strings:\n ${'$'}a = \"abc\" ascii wide nocase\n ${'$'}b = \"xyz\" wide ascii\n condition:\n any of them\n}"
        )
        assertEquals(2, combined.first().patterns.size)

        val wideOnly = HydraYaraLite.parse("rule W {\n meta:\n severity = 50\n strings:\n ${'$'}a = \"abc\" wide\n condition:\n any of them\n}")
        val ascii = apk("classes.dex" to "abc".toByteArray())
        val wide = apk("classes.dex" to utf16("abc"))
        try {
            assertEquals(0, HydraYaraLite.scanApk(ascii, wideOnly).size)
            assertEquals(1, HydraYaraLite.scanApk(wide, wideOnly).size)
        } finally { ascii.delete(); wide.delete() }
    }

    @Test
    fun singleMarkerDoesNotSatisfyTwoOfThem() {
        val rules = rule("One", 60, "2 of them", "android.permission.READ_SMS", "android.permission.BIND_DEVICE_ADMIN")
        val f = apk("AndroidManifest.xml" to utf16("android.permission.READ_SMS"))
        try { assertTrue(HydraYaraLite.scanApk(f, rules).isEmpty()) } finally { f.delete() }
    }
}
