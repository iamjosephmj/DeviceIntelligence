package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/** Unit tests for the dependency-free JSON reader. */
class JsonTest {
    @Test fun parses_object_with_typed_scalars() {
        val m = Json.parseObject("""{"a":1,"b":2.5,"c":"x","d":true,"e":null,"f":false}""")
        assertEquals(1L, m["a"])                 // integer -> Long
        assertEquals(2.5, m["b"])                // fractional -> Double
        assertEquals("x", m["c"])
        assertEquals(true, m["d"]); assertEquals(false, m["f"])
        assertNull(m["e"]); assertTrue(m.containsKey("e"))
    }

    @Test fun parses_nested_arrays_and_objects() {
        val m = Json.parseObject("""{"xs":[1,2,3],"o":{"k":"v"},"empty":[],"eo":{}}""")
        assertEquals(listOf(1L, 2L, 3L), m["xs"])
        @Suppress("UNCHECKED_CAST")
        assertEquals("v", (m["o"] as Map<String, Any?>)["k"])
        assertEquals(emptyList<Any?>(), m["empty"])
        assertTrue((m["eo"] as Map<*, *>).isEmpty())
    }

    @Test fun handles_string_escapes() {
        val m = Json.parseObject("""{"s":"a\"b\\c\/d\n\t\rA"}""")
        assertEquals("a\"b\\c/d\n\t\rA", m["s"])
    }

    @Test fun parses_negative_and_exponent_numbers() {
        val m = Json.parseObject("""{"neg":-42,"exp":1e3,"flt":-0.5}""")
        assertEquals(-42L, m["neg"])
        assertEquals(1000.0, m["exp"])
        assertEquals(-0.5, m["flt"])
    }

    @Test fun rejects_trailing_data() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("""{"a":1} junk""") }
    }
    @Test fun rejects_unterminated_string() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("\"abc") }
    }
    @Test fun rejects_bad_escape() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("\"a\\x\"") }
    }
    @Test fun rejects_missing_comma_or_brace() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("""{"a":1 "b":2}""") }
    }
    @Test fun rejects_bad_literal() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("nul") }
    }
    @Test fun parseObject_rejects_non_object() {
        assertThrows(IllegalArgumentException::class.java) { Json.parseObject("[1,2]") }
    }

    @Test fun parses_a_signed_content_shaped_document() {
        val doc = Json.parseObject(
            """{"schemaVersion":3,"type":"challenge","ts":1787,"signals":[{"id":"INTEL_0009","severity":"CRITICAL"}]}"""
        )
        assertEquals(3L, doc["schemaVersion"])
        @Suppress("UNCHECKED_CAST")
        val sigs = doc["signals"] as List<Map<String, Any?>>
        assertEquals("INTEL_0009", sigs[0]["id"])
    }
}
