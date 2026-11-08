package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F5 regression test (security/performance audit): Hydra's SYN-ACK must
 * advertise a real, RFC 1323-valid Window Scale option. The pre-fix code
 * emitted "3, 3, 0, 0" -- that's a 4-byte block, but a valid WS option is
 * kind=3, length=3, shift (3 bytes), so the old bytes did not round-trip
 * through a real TCP option parser as a Window Scale option at all.
 *
 * TcpPacketBuilder.build() itself needs a real TcpSession (backed by an open
 * SocketChannel), which this module can't construct without Android/sockets.
 * buildSynOptions() was split out specifically so this regression is
 * verifiable here: we take its output, lay it into a synthetic TCP header
 * exactly as build() does, and parse it back with the project's own
 * TcpHeader.parse() -- the same parser used on real TUN packets.
 */
class TcpPacketBuilderOptionsTest {

    private fun wrapInSyntheticTcpHeader(options: ByteArray): ByteArray {
        val tcpHeaderLength = 20 + options.size
        val packet = ByteArray(tcpHeaderLength)
        // source/dest port (irrelevant for this test), seq/ack = 0
        packet[12] = ((tcpHeaderLength / 4) shl 4).toByte() // data offset
        packet[13] = 0x02 // SYN flag, matches the real syn=true call site
        if (options.isNotEmpty()) System.arraycopy(options, 0, packet, 20, options.size)
        return packet
    }

    @Test
    fun synOptionsIncludeValidMssAndWindowScale() {
        val options = TcpPacketBuilder.buildSynOptions(localMss = 1460)
        val packet = wrapInSyntheticTcpHeader(options)

        val header = TcpHeader.parse(packet, ipHeaderLength = 0, ipTotalLength = packet.size)

        assertNotNull("TcpHeader.parse must accept Hydra's own SYN options block", header)
        assertEquals(1460, header!!.mss)
        assertEquals(
            "Window Scale shift must round-trip through the real parser, not just look right as raw bytes",
            TcpPacketBuilder.HYDRA_WINDOW_SCALE_SHIFT,
            header.windowScale
        )
    }

    @Test
    fun windowScaleShiftIsWithinRfc1323Bounds() {
        // RFC 1323: shift count must be <= 14.
        assertTrue(TcpPacketBuilder.HYDRA_WINDOW_SCALE_SHIFT in 0..14)
    }

    @Test
    fun optionsBlockLengthStaysFourByteAligned() {
        // TCP data offset is in 4-byte words; an unaligned options block
        // would corrupt the header length Hydra itself writes into the SYN-ACK.
        val options = TcpPacketBuilder.buildSynOptions(localMss = 1460)
        assertEquals(0, (20 + options.size) % 4)
    }
}
