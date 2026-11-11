package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class TrafficUsageBatcherTest {
    @Test
    fun smallPacketUpdatesAreMergedUntilThreshold() {
        val batcher = TrafficUsageBatcher(thresholdBytes = 100L)
        assertEquals(0L, batcher.addAndDrainIfReady(40))
        assertEquals(40L, batcher.pendingBytes())
        assertEquals(0L, batcher.addAndDrainIfReady(50))
        assertEquals(90L, batcher.pendingBytes())
        assertEquals(110L, batcher.addAndDrainIfReady(20))
        assertEquals(0L, batcher.pendingBytes())
    }

    @Test
    fun explicitFlushReturnsTailExactlyOnce() {
        val batcher = TrafficUsageBatcher(thresholdBytes = 1024L)
        assertEquals(0L, batcher.addAndDrainIfReady(512))
        assertEquals(512L, batcher.drain())
        assertEquals(0L, batcher.drain())
        assertEquals(0L, batcher.pendingBytes())
    }
}
