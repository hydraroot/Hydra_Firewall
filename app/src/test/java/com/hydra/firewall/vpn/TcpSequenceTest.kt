package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpSequenceTest {

    @Test
    fun add_wrapsAroundUnsigned32BitSpace() {
        assertEquals(0L, TcpSequence.add(0xFFFF_FFFFL, 1))
        assertEquals(0xFFFF_FFFFL, TcpSequence.add(0L, -1))
        assertEquals(5L, TcpSequence.add(0xFFFF_FFFEL, 7))
    }

    @Test
    fun compareHandlesNormalOrdering() {
        assertTrue(TcpSequence.before(100, 101))
        assertTrue(TcpSequence.after(101, 100))
        assertEquals(0, TcpSequence.compare(42, 42))
    }

    @Test
    fun compareHandlesWrapAround() {
        val nearWrap = 0xFFFF_FFF0L
        val afterWrap = 0x0000_0010L

        assertTrue(TcpSequence.before(nearWrap, afterWrap))
        assertTrue(TcpSequence.after(afterWrap, nearWrap))
    }

    @Test
    fun compareResolvesExactHalfSpaceBoundaryDeterministically() {
        val a = 0L
        val b = 0x8000_0000L

        // RFC 1982 serial number arithmetic leaves the ordering undefined
        // when two sequence numbers are exactly 2^31 apart. This
        // implementation resolves it deterministically by raw unsigned
        // value so that compare stays antisymmetric even at that boundary.
        assertEquals(-1, TcpSequence.compare(a, b))
        assertEquals(1, TcpSequence.compare(b, a))
    }

    @Test
    fun compareIsAntisymmetricAcrossRandomAndBoundaryValues() {
        val boundaryPairs = listOf(
            0L to 0x8000_0000L,
            0x8000_0000L to 0L,
            1L to 0x8000_0001L,
            0xFFFF_FFFFL to 0x7FFF_FFFFL
        )
        for ((a, b) in boundaryPairs) {
            assertEquals(
                "compare($a, $b) should be the negation of compare($b, $a)",
                -TcpSequence.compare(a, b),
                TcpSequence.compare(b, a)
            )
        }

        val random = java.util.Random(42)
        repeat(2000) {
            val a = random.nextLong() and 0xFFFF_FFFFL
            val b = random.nextLong() and 0xFFFF_FFFFL
            assertEquals(-TcpSequence.compare(a, b), TcpSequence.compare(b, a))
        }
    }

    @Test
    fun distanceIsForwardAndWrapAware() {
        assertEquals(50L, TcpSequence.distance(100, 150))
        assertEquals(16L, TcpSequence.distance(0xFFFF_FFF0L, 0))
        assertEquals(0L, TcpSequence.distance(123, 123))
    }

    @Test
    fun duplicateSequenceIsNotAfterExpected() {
        val expected = 1000L
        val duplicate = 900L
        assertFalse(TcpSequence.after(duplicate, expected))
    }
}
