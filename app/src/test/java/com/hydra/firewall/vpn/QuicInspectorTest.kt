package com.hydra.firewall.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuicInspectorTest {
    @Test fun invalidPacketIsNotQuic() {
        val r = QuicInspector.inspect(byteArrayOf(0x00))
        assertFalse(r.isQuic)
    }

    @Test fun longHeaderInitialIsRecognized() {
        val packet = byteArrayOf(0xC0.toByte(), 0, 0, 0, 1, 4, 1, 2, 3, 4, 0)
        val r = QuicInspector.inspect(packet)
        assertTrue(r.isQuic)
        assertTrue(r.isLongHeader)
        assertTrue(r.isInitial)
        assertTrue(r.version == 1L)
        assertTrue(r.dcidLength == 4)
    }
}
