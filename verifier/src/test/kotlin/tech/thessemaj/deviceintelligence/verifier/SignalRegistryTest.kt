package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SignalRegistryTest {
    private val registry = SignalRegistry.bundled

    @Test fun `bundled registry loads the active rows`() = assertEquals(61, registry.size)

    @Test fun `resolves a code to its meaning`() {
        val meta = registry["INTEL_0042"]!!
        assertEquals("native_integrity", meta.detector)
        assertEquals("text_integrity_divergence", meta.kind)
        assertEquals("CRITICAL", meta.severity)
    }

    @Test fun `retired codes are absent`() = assertNull(registry["INTEL_0020"])

    @Test fun `null-safe get`() = assertNull(registry[null])
}
