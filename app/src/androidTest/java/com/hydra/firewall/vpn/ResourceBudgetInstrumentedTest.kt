package com.hydra.firewall.vpn

import android.content.ComponentName
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ResourceBudgetInstrumentedTest {

    @Test
    fun vpnServiceIsRegisteredWithTheSystemVpnBindingPermission() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.hydra.firewall", context.packageName)
        val info = context.packageManager.getServiceInfo(
            ComponentName(context, FirewallVpnService::class.java),
            PackageManager.GET_META_DATA
        )
        assertEquals("android.permission.BIND_VPN_SERVICE", info.permission)
    }

    @Test
    fun tcpAndUdpResourceBudgetsRunOnAndroidRuntime() {
        val tcpBudget = BoundedSessionBudget(maxSessions = 2)
        val first = tcpBudget.tryAcquire()
        val second = tcpBudget.tryAcquire()
        assertNotNull(first)
        assertNotNull(second)
        assertEquals(2, tcpBudget.activeCount())
        assertTrue(tcpBudget.tryAcquire() == null)
        first!!.close()
        second!!.close()
        assertEquals(0, tcpBudget.activeCount())

        val udpBudget = BoundedUdpDatagramBudget(maxDatagrams = 2, maxBytes = 1024)
        assertTrue(udpBudget.tryReserve(512))
        assertTrue(udpBudget.tryReserve(512))
        assertTrue(!udpBudget.tryReserve(1))
        udpBudget.release(512)
        udpBudget.release(512)
        assertEquals(BoundedUdpDatagramBudget.Snapshot(0, 0), udpBudget.snapshot())
    }
}
