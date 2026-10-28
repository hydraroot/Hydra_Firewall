package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpReassemblyTest {
    @Test
    fun inOrderDataDeliversImmediately() {
        val r = TcpReassembly()
        val result = r.offer(100, "abc".toByteArray(), 100)
        assertEquals(1, result.delivered.size)
        assertEquals("abc", result.delivered[0].toString(Charsets.US_ASCII))
        assertEquals(103L, result.nextExpected)
    }

    @Test
    fun outOfOrderIsBufferedThenReleasedWhenGapArrives() {
        val r = TcpReassembly()
        val late = r.offer(106, "ghi".toByteArray(), 100)
        assertTrue(late.delivered.isEmpty())
        assertEquals(1, r.segmentCount())

        val first = r.offer(100, "abcdef".toByteArray(), 100)
        assertEquals(1, first.delivered.size)
        assertEquals("abcdefghi", first.delivered[0].toString(Charsets.US_ASCII))
        assertEquals(109L, first.nextExpected)
    }

    @Test
    fun duplicateDataDoesNotGrowBuffer() {
        val r = TcpReassembly()
        r.offer(100, "abc".toByteArray(), 100)
        val duplicate = r.offer(100, "abc".toByteArray(), 103)
        assertTrue(duplicate.delivered.isEmpty())
        assertEquals(0, r.bufferedBytes())
    }

    @Test
    fun overlappingOutOfOrderSegmentsAreMerged() {
        val r = TcpReassembly()
        r.offer(104, "efgh".toByteArray(), 100)
        val result = r.offer(100, "abcdef".toByteArray(), 100)
        assertEquals(1, result.delivered.size)
        assertEquals("abcdefgh", result.delivered[0].toString(Charsets.US_ASCII))
        assertEquals(108L, result.nextExpected)
    }

    @Test
    fun sequenceWrapIsHandled() {
        val r = TcpReassembly()
        val expected = 0xFFFF_FFFEL
        val buffered = r.offer(0L, "CD".toByteArray(), expected)
        assertTrue(buffered.delivered.isEmpty())
        val result = r.offer(expected, "AB".toByteArray(), expected)
        assertEquals(1, result.delivered.size)
        assertEquals("ABCD", result.delivered[0].toString(Charsets.US_ASCII))
        assertEquals(2L, result.nextExpected)
    }

    @Test
    fun farAheadSegmentIsRejected() {
        val r = TcpReassembly(maxAhead = 32)
        val result = r.offer(200, ByteArray(4) { 1 }, 100)
        assertEquals(TcpReassembly.ResultType.OUT_OF_WINDOW, result.type)
        assertTrue(result.delivered.isEmpty())
    }
}
