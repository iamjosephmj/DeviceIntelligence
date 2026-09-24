package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/** Tests the (non-verifying) token decoder + the signal-resolution helper. */
class TokenDecoderTest {
    private fun res(p: String) = javaClass.getResourceAsStream(p)!!.bufferedReader().use { it.readText() }.trim()

    @Test fun decodes_real_challenge_token_fixture() {
        val d = TokenDecoder().decode(res("/pixel-challenge.token"))
        assertEquals(3, d.schemaVersion)          // all fixtures are schemaVersion 3
        assertTrue("challenge carries a SIG binding", d.hasBinding)
    }

    @Test fun resolve_maps_known_signal_from_registry() {
        val reg = SignalRegistry.bundled
        val doc = mapOf<String, Any?>(
            "signals" to listOf(mapOf<String, Any?>("id" to "INTEL_0009", "detail" to "x")),
        )
        val out = Signals.resolve(doc, reg, Policy())
        assertEquals(1, out.size)
        assertEquals("INTEL_0009", out[0].id)
        assertNotEquals("?", out[0].detector)     // resolved from the registry
        assertEquals("x", out[0].detail)
    }

    @Test fun resolve_falls_back_for_unknown_signal() {
        val doc = mapOf<String, Any?>(
            "signals" to listOf(mapOf<String, Any?>("id" to "INTEL_9999", "severity" to "CRITICAL")),
        )
        val out = Signals.resolve(doc, SignalRegistry.bundled, Policy())
        assertEquals(1, out.size)
        assertEquals("INTEL_9999", out[0].id)
        assertEquals("?", out[0].detector)        // unknown -> "?"
        assertEquals("CRITICAL", out[0].severity) // severity taken from the signal
    }

    @Test fun resolve_returns_empty_when_no_signals() {
        assertTrue(Signals.resolve(mapOf<String, Any?>(), SignalRegistry.bundled, Policy()).isEmpty())
    }

    @Test fun device_parses_when_present_and_null_when_absent() {
        val d = Signals.device(mapOf("device" to mapOf<String, Any?>("api" to 34L, "abi" to "arm64-v8a", "model" to "Pixel")))
        assertEquals(34, d!!.api); assertEquals("arm64-v8a", d.abi); assertEquals("Pixel", d.model)
        assertNull(Signals.device(mapOf<String, Any?>()))
    }
}
