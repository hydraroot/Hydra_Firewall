package com.hydra.firewall.vpn

import com.hydra.firewall.vpn.ConnectionExplainer.Facts
import com.hydra.firewall.vpn.ConnectionExplainer.InstallSource
import com.hydra.firewall.vpn.ConnectionExplainer.Level
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionExplainerTest {
    private fun facts(
        host: String? = "93.184.216.34", domain: String? = null, port: Int = 443, protocol: String = "TCP",
        allowed: Boolean? = null, first: Boolean = false, blocklisted: Boolean = false, threat: String? = null,
        src: InstallSource = InstallSource.UNKNOWN, installed: Long? = null, updated: Long? = null, repeat: Int = 1
    ) = Facts(host, domain, port, protocol, allowed, first, blocklisted, threat, src, installed, updated, repeat)

    private fun es(f: Facts) = ConnectionExplainer.explain(f).map { it.es }

    @Test
    fun parseEndpointHandlesIpv4Ipv6AndGarbage() {
        assertEquals(ConnectionExplainer.Endpoint("1.2.3.4", 443), ConnectionExplainer.parseEndpoint("1.2.3.4:443"))
        assertEquals(ConnectionExplainer.Endpoint("2001:db8::1", 853), ConnectionExplainer.parseEndpoint("[2001:db8::1]:853"))
        assertEquals(ConnectionExplainer.Endpoint("host.example", 80), ConnectionExplainer.parseEndpoint(" host.example:80 "))
        assertNull(ConnectionExplainer.parseEndpoint("2001:db8::1"))       // IPv6 sin puerto
        assertNull(ConnectionExplainer.parseEndpoint("1.2.3.4:99999"))
        assertNull(ConnectionExplainer.parseEndpoint("1.2.3.4:abc"))
        assertNull(ConnectionExplainer.parseEndpoint(""))
        assertNull(ConnectionExplainer.parseEndpoint("[::1"))
    }

    @Test
    fun isIpLiteralNeverTreatsHostnamesAsIps() {
        assertTrue(ConnectionExplainer.isIpLiteral("8.8.8.8"))
        assertTrue(ConnectionExplainer.isIpLiteral("[2001:db8::1]"))
        assertTrue(ConnectionExplainer.isIpLiteral("fe80::1%wlan0"))
        assertFalse(ConnectionExplainer.isIpLiteral("example.com"))
        assertFalse(ConnectionExplainer.isIpLiteral("999.1.1.1"))
        assertFalse(ConnectionExplainer.isIpLiteral("1.2.3"))
    }

    @Test
    fun threatMatchIsDangerAndAlwaysFirst() {
        val r = ConnectionExplainer.explain(facts(domain = "bad.example", threat = "Feodo Tracker • botnet C2", first = true))
        assertEquals(Level.DANGER, r.first().level)
        assertTrue(r.first().es.contains("Feodo Tracker"))
        assertTrue(r.first().en.startsWith("Matches threat intelligence"))
        assertEquals(Level.DANGER, ConnectionExplainer.highestLevel(r))
    }

    @Test
    fun blocklistedDomainIsWarningAndNotPresentedAsNeutralInfo() {
        val r = es(facts(domain = "ads.tracker.example", blocklisted = true))
        assertTrue(r.any { it.contains("figura en las listas") })
        assertFalse(r.any { it.startsWith("Se conecta a") })
    }

    @Test
    fun ipWithoutDomainIsHonestAboutNotKnowingTheName() {
        val r = es(facts(domain = null))
        assertTrue(r.any { it.contains("sin un nombre de dominio conocido") && it.contains("nada lo confirma") })
    }

    @Test
    fun neverInventsADomainWhenNoneIsKnown() {
        val all = ConnectionExplainer.explain(facts(domain = null, host = null, port = 8443)).joinToString(" ") { it.es }
        assertFalse(all.contains("Se conecta a"))
    }

    @Test
    fun knownPortsGetPlainLanguageAndRiskyPortsAreCautious() {
        assertTrue(es(facts(port = 5228)).any { it.contains("Google Play Services") })
        val telnet = ConnectionExplainer.explain(facts(port = 23))
        assertTrue(telnet.any { it.level == Level.WARNING && it.es.contains("Telnet") })
        val ssh = es(facts(port = 4444))
        assertTrue(ssh.any { it.contains("aunque también software legítimo") })
        // puerto 80: aviso de falta de cifrado
        assertTrue(ConnectionExplainer.explain(facts(port = 80, domain = "example.com")).any { it.level == Level.NOTICE && it.es.startsWith("Sin cifrado") })
    }

    @Test
    fun installSourceAndAgeSignals() {
        assertTrue(es(facts(src = InstallSource.PLAY_STORE)).any { it == "Instalada desde Google Play." })
        val side = ConnectionExplainer.explain(facts(src = InstallSource.SIDELOADED))
        assertTrue(side.any { it.level == Level.NOTICE && it.es.contains("APK externa") })
        assertTrue(es(facts(installed = 0)).any { it.contains("menos de 24 horas") })
        assertTrue(es(facts(installed = 40, updated = 1)).any { it.contains("hace 1 día;") })
        assertFalse("recién instalada no repite lo de actualizada", es(facts(installed = 0, updated = 0)).any { it.contains("Se actualizó") })
    }

    @Test
    fun weakSignalsNeverEscalateAboveNotice() {
        val r = ConnectionExplainer.explain(facts(src = InstallSource.SIDELOADED, installed = 0, port = 9999, first = true, domain = null))
        assertTrue(r.none { it.level == Level.WARNING || it.level == Level.DANGER })
    }

    @Test
    fun retryingBlockedAppIsExplained() {
        assertTrue(es(facts(allowed = false, repeat = 35)).any { it.contains("Insistió 35 veces") })
        assertFalse(es(facts(allowed = true, repeat = 35)).any { it.contains("Insistió") })
        assertFalse(es(facts(allowed = null, repeat = 35)).any { it.contains("Insistió") })
    }

    @Test
    fun resultIsSortedBySeverityAndCapped() {
        val r = ConnectionExplainer.explain(
            facts(domain = "x.example", blocklisted = true, threat = "t", first = true, src = InstallSource.SIDELOADED, installed = 0, port = 23, allowed = false, repeat = 50),
            max = 4
        )
        assertEquals(4, r.size)
        assertEquals(Level.DANGER, r[0].level)
        for (i in 1 until r.size) assertTrue(r[i - 1].level.ordinal >= r[i].level.ordinal)
    }

    @Test
    fun englishAndSpanishAreBothFilledForEveryReason() {
        val r = ConnectionExplainer.explain(
            facts(domain = "x.example", blocklisted = true, threat = "t", first = true, src = InstallSource.SIDELOADED, installed = 0, port = 80, allowed = false, repeat = 50), max = 20
        )
        assertTrue(r.isNotEmpty())
        r.forEach { assertTrue(it.es.isNotBlank() && it.en.isNotBlank() && it.es != it.en) }
    }
}
