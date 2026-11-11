package com.hydra.firewall.vpn

import java.net.InetAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionPolicyCadenceTest {
    private fun key() = SessionKey(
        protocol = UidResolver.PROTOCOL_TCP,
        srcAddr = InetAddress.getByName("10.0.0.2"),
        srcPort = 12345,
        dstAddr = InetAddress.getByName("203.0.113.10"),
        dstPort = 443
    )

    @Test
    fun tcpAndUdpPolicyChecksAreBoundedToOneSecond() {
        SocketChannel.open().use { socket ->
            val tcp = TcpSession(key(), 10001, "example.app", 1460, 0, 1460, socket, 1L, 1L)
            assertTrue(tcp.needsPolicyRecheck(10_000L))
            tcp.markPolicyChecked(10_000L)
            assertFalse(tcp.needsPolicyRecheck(10_999L))
            assertTrue(tcp.needsPolicyRecheck(11_000L))
        }
        DatagramChannel.open().use { datagram ->
            val udpKey = key().copy(protocol = UidResolver.PROTOCOL_UDP)
            val udp = UdpSession(udpKey, 10001, "example.app", datagram)
            assertTrue(udp.needsPolicyRecheck(20_000L))
            udp.markPolicyChecked(20_000L)
            assertFalse(udp.needsPolicyRecheck(20_999L))
            assertTrue(udp.needsPolicyRecheck(21_000L))
        }
    }

    @Test
    fun quicPolicyCacheExpiresAfterOneSecondAndCanBeInvalidated() {
        DatagramChannel.open().use { datagram ->
            val udp = UdpSession(key().copy(protocol = UidResolver.PROTOCOL_UDP), 10001, "example.app", datagram)
            val incomplete = QuicProtection.Result(false, reason = "NO_DNS_CORRELATION", version = 1L)
            udp.cacheQuicResult(incomplete, 4_000L)
            assertNull("an unknown domain must be inspected again when DNS correlation may arrive", udp.cachedQuicResult(4_001L))

            val allowed = QuicProtection.Result(false, domain = "upload.example", version = 1L, cacheable = true)
            udp.cacheQuicResult(allowed, 5_000L)
            assertEquals(allowed, udp.cachedQuicResult(5_999L))
            assertNull(udp.cachedQuicResult(6_000L))

            val blocked = QuicProtection.Result(true, reason = "QUIC_BLOCKLIST_DOMAIN", domain = "bad.example", version = 1L, cacheable = true)
            udp.cacheQuicResult(blocked, 7_000L)
            assertEquals(blocked, udp.cachedQuicResult(7_001L))
            udp.invalidateQuicResult()
            assertNull(udp.cachedQuicResult(7_002L))
        }
    }
}
