package tech.thessemaj.deviceintelligence.sample.signal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The catalogue is generated from `tools/registry/signals-registry.json`, so the
 * failure mode worth guarding is drift: a signal added to the registry without
 * regenerating, which reaches the screen with no explanation and looks exactly like
 * a signal that has none.
 */
class SignalCatalogueTest {

    @Test fun `every code in the registry has a catalogue entry`() {
        val registry = File("../../tools/registry/signals-registry.json")
        assertTrue("registry not found at ${registry.absolutePath}", registry.exists())

        // Plain regex rather than a JSON parser: org.json is an Android stub on the
        // unit-test classpath and throws "not mocked" unless the whole module opts in.
        val codes = Regex("\"id\"\\s*:\\s*\"(INTEL_\\d+)\"")
            .findAll(registry.readText())
            .map { it.groupValues[1] }
            .toList()
        assertTrue("no codes parsed from the registry", codes.isNotEmpty())

        val missing = codes.filter { SignalCatalogue.of(it) == null }
        assertTrue(
            "not in the catalogue — run tools/registry/gen-signal-catalogue.py: $missing",
            missing.isEmpty(),
        )
        assertEquals(codes.size, SignalCatalogue.entries.size)
    }

    @Test fun `an unknown code resolves to nothing rather than throwing`() {
        // Registry drift on the wire is expected and must not crash the screen.
        assertNull(SignalCatalogue.of("INTEL_9999"))
        assertNull(SignalCatalogue.of("INTEL_UNKNOWN"))
        assertNull(SignalCatalogue.of(""))
    }

    @Test fun `codes are filed under the family their detector belongs to`() {
        assertEquals(SignalGroup.Attestation, SignalCatalogue.of("INTEL_0000")?.group)
        assertEquals(SignalGroup.RuntimeInstrumentation, SignalCatalogue.of("INTEL_0001")?.group)
        assertEquals(SignalGroup.RuntimeInstrumentation, SignalCatalogue.of("INTEL_0003")?.group)
        assertEquals(SignalGroup.AntiAnalysis, SignalCatalogue.of("INTEL_0004")?.group)
        assertEquals(SignalGroup.PackageIntegrity, SignalCatalogue.of("INTEL_0020")?.group)
    }

    @Test fun `retired codes are flagged`() {
        // A retired code should never arrive; if one does, the resolving registry is stale.
        assertTrue(SignalCatalogue.of("INTEL_0034")!!.retired)
        assertFalse(SignalCatalogue.of("INTEL_0000")!!.retired)
    }

    @Test fun `every entry carries a meaning`() {
        SignalCatalogue.entries.forEach {
            assertNotNull(it.meaning)
            assertTrue("${it.name} has no meaning string", it.meaning != 0)
        }
    }
}
