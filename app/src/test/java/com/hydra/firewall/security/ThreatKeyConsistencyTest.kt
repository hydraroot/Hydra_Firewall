package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ThreatKeyConsistencyTest {
    private val rx = Regex("\"(MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE[A-Za-z0-9+/=]+)\"")

    private fun find(rel: String): File =
        listOf(File(rel), File("app/$rel")).first { it.isFile }

    @Test
    fun gradleAndVerifierDefaultKeysMatch() {
        val g = rx.find(find("build.gradle.kts").readText())!!.groupValues[1]
        val k = rx.find(find("src/main/java/com/hydra/firewall/security/ThreatSignatureVerifier.kt").readText())!!.groupValues[1]
        assertEquals(g, k)
    }

    @Test
    fun envBlankTreatedAsMissingInGradle() {
        assertTrue(find("build.gradle.kts").readText().contains("firstOrNull { it.isNotEmpty() }"))
    }
}
