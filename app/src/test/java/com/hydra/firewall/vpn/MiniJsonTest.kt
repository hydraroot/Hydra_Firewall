package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class MiniJsonTest {
    @Test
    fun roundTripsNestedValuesAndEscapes() {
        val original = linkedMapOf<String, Any?>(
            "text" to "línea1\nlínea2\t\"comillas\" \\ barra \u0001 ñ 日本",
            "n" to 42L, "neg" to -7L, "d" to 1.5, "yes" to true, "no" to false, "nil" to null,
            "list" to listOf(1L, "a", listOf<Any?>(), emptyMap<String, Any?>()),
            "obj" to linkedMapOf<String, Any?>("k" to "v")
        )
        assertEquals(original, MiniJson.parse(MiniJson.write(original)))
        assertEquals(original, MiniJson.parse(MiniJson.write(original, pretty = true)))
    }

    @Test
    fun parsesNumbersAsLongOrDouble() {
        val l = MiniJson.parse("[1, -2, 3.0, 4e2, 9223372036854775807]") as List<*>
        assertEquals(listOf(1L, -2L, 3.0, 400.0, Long.MAX_VALUE), l)
    }

    @Test
    fun decodesUnicodeEscapes() {
        assertEquals("Añ", MiniJson.parse("\"A\\u00f1\""))
    }

    @Test
    fun rejectsMalformedInput() {
        val bad = listOf("", "{", "[1,", "{\"a\" 1}", "{\"a\":1,}", "[1 2]", "tru", "\"abc", "{\"a\":1} x", "[\"\\q\"]", "-", "99999999999999999999")
        for (b in bad) {
            try { MiniJson.parse(b); fail("debía fallar: $b") } catch (e: IllegalArgumentException) { /* ok */ }
        }
    }

    @Test
    fun rejectsExcessiveNesting() {
        val deep = "[".repeat(200) + "]".repeat(200)
        try { MiniJson.parse(deep); fail("debía fallar por anidación") } catch (e: IllegalArgumentException) { /* ok */ }
    }

    @Test
    fun writeRejectsNonFiniteNumbers() {
        try { MiniJson.write(Double.NaN); fail("NaN") } catch (e: IllegalArgumentException) { /* ok */ }
    }

    @Test
    fun emptyContainersAndNull() {
        assertTrue(MiniJson.parse("{}") is Map<*, *>)
        assertTrue((MiniJson.parse("[]") as List<*>).isEmpty())
        assertNull(MiniJson.parse("null"))
    }
}
