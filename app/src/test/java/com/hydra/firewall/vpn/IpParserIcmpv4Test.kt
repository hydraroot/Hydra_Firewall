package com.hydra.firewall.vpn

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IpParserIcmpv4Test {
    @Test
    fun parsesIpv4EchoRequestAndLocalHandlerReplies() {
        val request = buildEchoRequest("10.0.0.3", "10.0.0.2")
        val parsed = IpParser.parse(request)
        assertTrue(parsed is IpParser.Result.Icmpv4)
        parsed as IpParser.Result.Icmpv4
        assertEquals(8, parsed.type)
        assertEquals(0, parsed.code)

        val sink = ByteArrayOutputStream()
        val writer = TunPacketWriter(sink)
        assertTrue(Icmpv4Handler.handle(parsed.packet, parsed.header, writer))
        val reply = sink.toByteArray()
        assertEquals(28, reply.size)
        assertEquals(4, (reply[0].toInt() ushr 4) and 0xF)
        assertEquals(0, reply[20].toInt() and 0xFF)
        assertEquals(0, InternetChecksum.compute(reply, 0, 20))
        assertEquals(0, InternetChecksum.compute(reply, 20, 8))
    }

    private fun buildEchoRequest(src: String, dst: String): ByteArray {
        val packet = ByteArray(28)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 28
        packet[8] = 64
        packet[9] = IPv4Header.PROTOCOL_ICMP.toByte()
        val srcBytes = InetAddress.getByName(src).address
        val dstBytes = InetAddress.getByName(dst).address
        srcBytes.copyInto(packet, destinationOffset = 12)
        dstBytes.copyInto(packet, destinationOffset = 16)
        packet[20] = 8
        packet[21] = 0
        packet[24] = 0x12
        packet[25] = 0x34
        packet[26] = 0x00
        packet[27] = 0x01
        val icmpChecksum = InternetChecksum.checksum(packet, 20, 8)
        packet[22] = (icmpChecksum ushr 8).toByte()
        packet[23] = icmpChecksum.toByte()
        val ipChecksum = InternetChecksum.checksum(packet, 0, 20)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = ipChecksum.toByte()
        return packet
    }
}
