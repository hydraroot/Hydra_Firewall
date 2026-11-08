package com.hydra.firewall.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class Ipv6FragmentReassemblerTest {
    /** Fragmento IPv6 con protocolo UDP; [ext] antepone un Hop-by-Hop de 8 bytes antes del Fragment header. */
    private fun frag(id: Long, offset: Int, more: Boolean, payload: ByteArray, ext: Boolean = false, src: Int = 1): ByteArray {
        val extLen = if (ext) 8 else 0
        val total = 40 + extLen + 8 + payload.size
        val p = ByteArray(total)
        p[0] = 0x60
        val pl = total - 40
        p[4] = (pl ushr 8).toByte(); p[5] = pl.toByte()
        p[6] = if (ext) 0 else 44
        p[7] = 64
        p[8 + 15] = src.toByte(); p[24 + 15] = 2
        var o = 40
        if (ext) { p[o] = 44; p[o + 1] = 0; o += 8 }
        p[o] = 17
        val field = ((offset / 8) shl 3) or (if (more) 1 else 0)
        p[o + 2] = (field ushr 8).toByte(); p[o + 3] = field.toByte()
        p[o + 4] = (id ushr 24).toByte(); p[o + 5] = (id ushr 16).toByte(); p[o + 6] = (id ushr 8).toByte(); p[o + 7] = id.toByte()
        System.arraycopy(payload, 0, p, o + 8, payload.size)
        return p
    }

    private fun reassemble(sizes: List<Int>, ext: Boolean, order: List<Int> = sizes.indices.toList()): ByteArray? {
        val ra = Ipv6FragmentReassembler()
        val offsets = sizes.runningFold(0) { acc, n -> acc + n }
        var out: ByteArray? = null
        for (i in order) {
            val last = i == sizes.size - 1
            out = ra.accept(frag(5, offsets[i], !last, ByteArray(sizes[i]) { (i + 1).toByte() }, ext)) ?: out
        }
        return out
    }

    @Test fun lastFragmentSmallerThanTheOthersStillReassembles() {
        val out = reassemble(listOf(16, 16, 8), ext = false)
        assertNotNull("el último fragmento siempre es más chico en tráfico real", out)
        assertEquals(40 + 40, out!!.size)
        assertEquals(40, ((out[4].toInt() and 0xFF) shl 8) or (out[5].toInt() and 0xFF))
        assertEquals(17, out[6].toInt() and 0xFF)
        assertArrayEquals(ByteArray(16) { 1 } + ByteArray(16) { 2 } + ByteArray(8) { 3 }, out.copyOfRange(40, 80))
    }

    @Test fun fragmentsArrivingOutOfOrderReassemble() {
        val out = reassemble(listOf(16, 8, 16, 8), ext = false, order = listOf(3, 1, 0, 2))
        assertNotNull(out)
        assertEquals(40 + 48, out!!.size)
    }

    @Test fun extensionHeaderBeforeFragmentHeaderIsPatchedCorrectly() {
        val out = reassemble(listOf(16, 8), ext = true)
        assertNotNull(out)
        assertEquals("la base sigue apuntando al Hop-by-Hop", 0, out!![6].toInt() and 0xFF)
        assertEquals("el Hop-by-Hop apunta ahora a UDP, no al Fragment header", 17, out[40].toInt() and 0xFF)
        assertEquals(8 + 24, ((out[4].toInt() and 0xFF) shl 8) or (out[5].toInt() and 0xFF))
        assertEquals(40 + 8 + 24, out.size)
    }

    @Test fun differentSourceOrTrafficClassDoesNotMix() {
        val ra = Ipv6FragmentReassembler()
        assertNull(ra.accept(frag(9, 0, true, ByteArray(16), src = 1)))
        // misma id pero otro origen: es otra entrada, no completa la primera
        assertNull(ra.accept(frag(9, 16, false, ByteArray(8), src = 2)))
        val tampered = frag(9, 16, false, ByteArray(8), src = 1).also { it[7] = 1 } // hop limit distinto
        assertNull(ra.accept(tampered))
    }

    @Test fun overlappingFragmentsAreRejected() {
        val ra = Ipv6FragmentReassembler()
        assertNull(ra.accept(frag(3, 0, true, ByteArray(16))))
        assertNull(ra.accept(frag(3, 8, false, ByteArray(16))))
    }
}
