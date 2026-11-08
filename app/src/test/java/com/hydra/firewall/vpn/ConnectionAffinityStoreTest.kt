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
        val entry = store.lookup(UidResolver.PROTOCOL_TCP, v4, 40123, now = 1_200L)
        assertEquals(10042, entry?.uid)
        assertEquals("com.example.app", entry?.packageName)
    }

    // F3 fix: TTLs were shrunk from 30s/15s to 800ms/500ms so affinity covers
    // only the real /proc/net resolution race, not a whole app "session" --
    // see ConnectionAffinityStore.Companion for why the old windows let
    // unrelated apps collide on a reused ephemeral port.
    @Test
    fun tcpAffinityExpiresAfterBoundedWindow() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_TCP, v4, 40123, 10042, null, now = 1_000L)
        assertNull(store.lookup(UidResolver.PROTOCOL_TCP, v4, 40123, now = 1_801L))
    }

    @Test
    fun udpAffinityHasShorterWindow() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_UDP, v4, 40123, 10042, null, now = 1_000L)
        assertNull(store.lookup(UidResolver.PROTOCOL_UDP, v4, 40123, now = 1_501L))
    }

    @Test
    fun tcpAffinityStillAliveJustBeforeExpiry() {
        val store = ConnectionAffinityStore()
        store.remember(UidResolver.PROTOCOL_TCP, v4, 40123, 10042, null, now = 1_000L)
        assertEquals(10042, store.lookup(UidResolver.PROTOCOL_TCP, v4, 40123, now = 1_799L)?.uid)
    }
}
