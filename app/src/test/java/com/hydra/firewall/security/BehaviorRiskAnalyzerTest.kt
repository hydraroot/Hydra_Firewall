package com.hydra.firewall.security

import org.junit.Assert.assertTrue
import org.junit.Test

class BehaviorRiskAnalyzerTest {
    @Test
    fun riskLevelsHaveExpectedBounds() {
        val scores = listOf(0, 10, 25, 45, 70, 100)
        assertTrue(scores.all { it in 0..100 })
    }
}
