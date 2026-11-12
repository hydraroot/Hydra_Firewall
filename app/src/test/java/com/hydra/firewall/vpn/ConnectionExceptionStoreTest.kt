package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionExceptionStoreTest {
    @Test
    fun permanentExceptionsAreRestrictedToRegularApplicationUids() {
        assertFalse(ConnectionExceptionStore.canPersistPermanentForUid(0))
        assertFalse(ConnectionExceptionStore.canPersistPermanentForUid(1051))
        assertFalse(ConnectionExceptionStore.canPersistPermanentForUid(-1))
        assertTrue(ConnectionExceptionStore.canPersistPermanentForUid(10000))
        assertTrue(ConnectionExceptionStore.canPersistPermanentForUid(10234))
    }

    @Test
    fun domainAndEndpointExceptionsRoundTripWithoutBroadeningScope() {
        val entries = listOf(
            ConnectionExceptionStore.Entry(
                uid = 1051,
                kind = ConnectionExceptionStore.Kind.DOMAIN,
                domain = "firebaselogging.googleapis.com",
                expiresAt = 1_800_000_000_000L
            ),
            ConnectionExceptionStore.Entry(
                uid = 0,
                kind = ConnectionExceptionStore.Kind.ENDPOINT,
                ip = "192.168.1.1",
                protocol = "TCP",
                port = 853,
                expiresAt = 1_800_000_000_000L
            ),
            ConnectionExceptionStore.Entry(
                uid = 10234,
                kind = ConnectionExceptionStore.Kind.ENDPOINT,
                ip = "203.0.113.8",
                protocol = "UDP",
                port = 443,
                packageName = "com.example.testapp",
                expiresAt = 0L
            )
        )
        val decoded = ConnectionExceptionStore.decode(ConnectionExceptionStore.encode(entries))
        assertEquals(entries, decoded)
    }

    @Test
    fun decoderRejectsPermanentSystemUidExceptions() {
        val forged = """[{"uid":1051,"kind":"DOMAIN","domain":"example.com","expires":0},{"uid":10001,"kind":"DOMAIN","domain":"example.com","package":"com.example.app","expires":0}]"""
        val decoded = ConnectionExceptionStore.decode(forged)
        assertEquals(1, decoded.size)
        assertEquals(10001, decoded.single().uid)
        assertEquals("com.example.app", decoded.single().packageName)
    }

    @Test
    fun decoderRejectsNegativeExpiryInsteadOfTreatingItAsPermanent() {
        val raw = """[{"uid":1051,"kind":"DOMAIN","domain":"example.com","expires":-1}]"""
        assertTrue(ConnectionExceptionStore.decode(raw).isEmpty())
    }

    @Test
    fun decoderStripsPackageIdentityFromSystemUidExceptions() {
        val raw = """[{"uid":1051,"kind":"DOMAIN","domain":"example.com","package":"com.example.app","expires":1800000000000}]"""
        val decoded = ConnectionExceptionStore.decode(raw)
        assertEquals(1, decoded.size)
        assertEquals(null, decoded.single().packageName)
    }

    @Test
    fun decoderRejectsAppUidExceptionWithoutPackageIdentity() {
        val raw = """[{"uid":10001,"kind":"DOMAIN","domain":"example.com","expires":0}]"""
        assertTrue(ConnectionExceptionStore.decode(raw).isEmpty())
    }


    @Test
    fun appExceptionDoesNotFollowARecycledOrSharedUidToAnotherPackage() {
        val entry = ConnectionExceptionStore.Entry(
            uid = 10234,
            kind = ConnectionExceptionStore.Kind.DOMAIN,
            domain = "example.com",
            packageName = "com.example.original",
            expiresAt = 0L
        )
        assertTrue(ConnectionExceptionStore.matchesScope(entry, 10234, "com.example.original"))
        assertFalse(ConnectionExceptionStore.matchesScope(entry, 10234, "com.example.other"))
        assertFalse(ConnectionExceptionStore.matchesScope(entry, 10234, null))
        assertFalse(ConnectionExceptionStore.matchesScope(entry, 10235, "com.example.original"))
    }

    @Test
    fun sharedSystemUidScopeDoesNotAcceptPermanentAppPackageIdentity() {
        val entry = ConnectionExceptionStore.Entry(
            uid = 1051,
            kind = ConnectionExceptionStore.Kind.DOMAIN,
            domain = "example.com",
            expiresAt = 100L
        )
        assertTrue(ConnectionExceptionStore.matchesScope(entry, 1051, null))
        assertTrue(ConnectionExceptionStore.matchesScope(entry, 1051, "system.netd"))
        assertFalse(ConnectionExceptionStore.matchesScope(entry, 0, null))
    }

    @Test
    fun expiryIsExplicitAndPermanentEntriesDoNotExpire() {
        val temp = ConnectionExceptionStore.Entry(1051, ConnectionExceptionStore.Kind.DOMAIN, domain = "example.com", expiresAt = 100L)
        val permanent = ConnectionExceptionStore.Entry(10001, ConnectionExceptionStore.Kind.DOMAIN, domain = "example.com", packageName = "com.example.app", expiresAt = 0L)
        assertTrue(temp.isExpired(100L))
        assertFalse(temp.isExpired(99L))
        assertFalse(permanent.isExpired(Long.MAX_VALUE))
    }
}
