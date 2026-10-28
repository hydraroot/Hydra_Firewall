package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetAddress

class ConnectionAffinityStoreTest {
    private val v4 = InetAddress.getByName("10.0.0.2")

    @Test
    fun remembersAndFindsSameLocalEndpoint() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_TCP, v4, 40123, 10042, "com.example.app", now = 1_000L)
        val entry = store.lookup(UidResolver.PROTOCOL_TCP, v4, 40123, now = 5_000L)
        assertEquals(10042, entry?.uid)
        assertEquals("com.example.app", entry?.packageName)
    }

    @Test
    fun tcpAffinityExpiresAfterBoundedWindow() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_TCP, v4, 40123, 10042, null, now = 1_000L)
        assertNull(store.lookup(UidResolver.PROTOCOL_TCP, v4, 40123, now = 36_001L))
    }

    @Test
    fun udpAffinityHasShorterWindow() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_UDP, v4, 40123, 10042, null, now = 1_000L)
        assertNull(store.lookup(UidResolver.PROTOCOL_UDP, v4, 40123, now = 16_001L))
    }
}
