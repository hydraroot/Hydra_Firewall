package com.hydra.firewall.vpn

import java.net.InetAddress
import java.nio.channels.SocketChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regresion del cuelgue de subidas (backup de WhatsApp): la ventana anunciada debe ir escalada
 * cuando se negocio Window Scale, y nunca prometer mas espacio del que el buffer realmente tiene.
 */
class TcpSessionWindowTest {

    private fun session(shift: Int): Pair<TcpSession, SocketChannel> {
        val channel = SocketChannel.open()
        val key = SessionKey(
            protocol = 6,
            srcAddr = InetAddress.getByName("10.0.0.2"),
            srcPort = 40000,
            dstAddr = InetAddress.getByName("203.0.113.10"),
            dstPort = 443
        )
        val s = TcpSession(
            key = key, uid = 10000, packageName = "test", peerMss = 1460, peerWindowScale = 7,
            localMss = 1460, channel = channel, clientInitialSeq = 1000L, localInitialSeq = 5000L
        )
        s.advertisedWindowShift = shift
        return s to channel
    }

    @Test
    fun unscaledWindowIsCappedAt65535() {
        val (s, ch) = session(shift = 0)
        try {
            assertEquals(65535, s.advertisedReceiveWindow())
        } finally { ch.close() }
    }

    @Test
    fun scaledWindowIsFreeSpaceDividedByScale() {
        val (s, ch) = session(shift = 7)
        try {
            assertEquals(TcpSession.RECEIVE_BUFFER_LIMIT ushr 7, s.advertisedReceiveWindow())
        } finally { ch.close() }
    }

    @Test
    fun synWindowIsNeverScaled() {
        val (s, ch) = session(shift = 7)
        try {
            assertEquals(65535, s.advertisedReceiveWindow(syn = true))
        } finally { ch.close() }
    }

    @Test
    fun windowNeverPromisesMoreThanTheBufferCanHold() {
        val (s, ch) = session(shift = 7)
        try {
            s.toSocketBytes = TcpSession.RECEIVE_BUFFER_LIMIT - 100
            val raw = s.advertisedReceiveWindow()
            assertTrue((raw shl 7) <= 100)
            s.toSocketBytes = TcpSession.RECEIVE_BUFFER_LIMIT
            assertEquals(0, s.advertisedReceiveWindow())
        } finally { ch.close() }
    }

    @Test
    fun bufferedOutOfOrderBytesShrinkTheAdvertisedWindow() {
        val (s, ch) = session(shift = 7)
        try {
            s.reassembly.offer(sequence = 2000L, payload = ByteArray(5000), expectedSeq = 1000L)
            val buffered = s.reassembly.bufferedBytes()
            assertTrue(buffered > 0)
            assertEquals(
                (TcpSession.RECEIVE_BUFFER_LIMIT - buffered) ushr 7,
                s.advertisedReceiveWindow()
            )
        } finally { ch.close() }
    }

    @Test
    fun windowUpdateIsNeededOnlyAfterMeaningfulDrain() {
        val (s, ch) = session(shift = 7)
        try {
            s.toSocketBytes = TcpSession.RECEIVE_BUFFER_LIMIT
            assertEquals(0, s.advertisedReceiveWindow())
            s.toSocketBytes = TcpSession.RECEIVE_BUFFER_LIMIT - 1000
            assertFalse(s.needsWindowUpdate())
            s.toSocketBytes = 0
            assertTrue(s.needsWindowUpdate())
            s.advertisedReceiveWindow()
            assertFalse(s.needsWindowUpdate())
        } finally { ch.close() }
    }
}
