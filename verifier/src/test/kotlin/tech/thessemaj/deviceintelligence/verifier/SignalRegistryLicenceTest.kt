package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/**
 * The app-identity codes must resolve before anything emits them — an unregistered
 * id reaches the backend as INTEL_UNKNOWN, which reads as "registry is stale" rather
 * than as the finding it actually is.
 */
class SignalRegistryLicenceTest {

    @Test fun licence_signals_are_registered() {
        for (id in listOf("INTEL_0045", "INTEL_0046")) {
            val row = SignalRegistry.bundled[id]
            assertNotNull("$id must be in the registry", row)
            assertTrue("$id needs a title", row!!.title.isNotEmpty())
            assertTrue("$id needs a description", row.description.isNotEmpty())
            assertEquals("$id belongs to the attestation detector", "attestation", row.detector)
        }
    }

    @Test fun the_mismatch_signal_outranks_the_licensing_one() {
        // INTEL_0045 is tampering, INTEL_0046 is a stale licence table. Conflating them
        // would let a billing problem read as a compromise.
        assertEquals("CRITICAL", SignalRegistry.bundled["INTEL_0045"]!!.severity)
        assertEquals("HIGH", SignalRegistry.bundled["INTEL_0046"]!!.severity)
    }

    @Test fun patch_signals_are_registered() {
        for (id in listOf("INTEL_0047", "INTEL_0048")) {
            val row = SignalRegistry.bundled[id]
            assertNotNull("$id must be in the registry", row)
            assertEquals("attestation", row!!.detector)
            assertTrue("$id needs a description", row.description.isNotEmpty())
        }
    }
}
