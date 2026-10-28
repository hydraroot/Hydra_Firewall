package com.hydra.firewall.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HydraAiEngineTest {
    @Test
    fun modelProducesBoundedRiskScore() {
        val means = List(14) { 0.0 }
        val scales = List(14) { 1.0 }
        val weights = List(14) { 0.0 }
        val json = """
            {
              "model_version":"test-model",
              "means":[${means.joinToString(",")}],
              "scales":[${scales.joinToString(",")}],
              "weights":[${weights.joinToString(",")}],
              "bias":0.0
            }
        """.trimIndent()
        HydraAiEngine.loadModelForTest(json)
        val result = HydraAiEngine.predict(
            HydraAiEngine.BehaviorFeatures(
                connections = 1,
                uniqueDestinations = 1,
                dnsQueries = 1,
                dnsBlocks = 0,
                tlsAlerts = 0,
                unusualPorts = 0,
                recentConnections = 1,
                newDestinations = 0,
                sniBlocks = 0
            )
        )
        assertNotNull(result)
        assertEquals(50, result!!.score)
        assertTrue(result.score in 0..100)
    }
}
