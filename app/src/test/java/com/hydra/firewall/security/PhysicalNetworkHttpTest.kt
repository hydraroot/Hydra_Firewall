package com.hydra.firewall.security

import java.net.URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhysicalNetworkHttpTest {
    @Test
    fun resolvesRelativeHttpsRedirectOnSameAuthority() {
        val resolved = PhysicalNetworkHttp.resolveHttpsRedirect(
            URL("https://feeds.example.test/v1/pack.json"),
            "../v2/pack.json"
        )
        assertEquals("https://feeds.example.test/v2/pack.json", resolved.toString())
    }

    @Test
    fun acceptsHttpsRedirectToASeparateHost() {
        val resolved = PhysicalNetworkHttp.resolveHttpsRedirect(
            URL("https://github.com/release"),
            "https://objects.githubusercontent.com/download/pack"
        )
        assertEquals("objects.githubusercontent.com", resolved.host)
        assertEquals("https", resolved.protocol)
    }

    @Test
    fun rejectsCredentialBearingInitialUrl() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            PhysicalNetworkHttp.validateInitialHttpsUrl("https://user:password@example.test/feed.json")
        }
    }

    @Test
    fun rejectsHttpDowngrade() {
        assertThrows(IllegalArgumentException::class.java) {
            PhysicalNetworkHttp.resolveHttpsRedirect(URL("https://example.test/a"), "http://example.test/b")
        }
    }

    @Test
    fun rejectsMissingLocation() {
        assertThrows(IllegalArgumentException::class.java) {
            PhysicalNetworkHttp.resolveHttpsRedirect(URL("https://example.test/a"), " ")
        }
    }

    @Test
    fun rejectsCredentialBearingRedirect() {
        assertThrows(IllegalArgumentException::class.java) {
            PhysicalNetworkHttp.resolveHttpsRedirect(
                URL("https://example.test/a"),
                "https://user:password@example.test/b"
            )
        }
    }
}
