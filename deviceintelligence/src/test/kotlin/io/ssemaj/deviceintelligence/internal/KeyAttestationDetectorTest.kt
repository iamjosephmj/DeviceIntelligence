package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Smoke tests for [KeyAttestationDetector] structural invariants.
 *
 * The detector's full integration path (KeyStore.getInstance,
 * KeyPairGenerator with attestation challenge, X509 chain walk,
 * KeyDescription parse) is exercised end-to-end by the sample app
 * at `samples/minimal` against a real Android runtime — it cannot
 * run in pure JVM unit tests because `AndroidKeyStore` is a
 * device-side service.
 *
 * These tests cover only the parts that DO survive in a JVM-only
 * test runner (no Robolectric on the classpath): the stable
 * detector id and the test-only cache reset hook.
 *
 * The verdict and parser components carry their own deep coverage
 * via [IntegrityVerdictTest] and [KeyDescriptionParserTest].
 */
class KeyAttestationDetectorTest {

    @Test
    fun `detector id matches the F14 contract`() {
        // Stable identifier — backends key on this. Any change is a
        // wire-format break and would need a corresponding bump.
        assertEquals("F14.key_attestation", KeyAttestationDetector.id)
    }

    @Test
    fun `resetForTest does not throw before any evaluate call`() {
        // Callable from a fresh process state to make a TestRig-style
        // fixture deterministic. Must not assume the cache has been
        // populated yet.
        KeyAttestationDetector.resetForTest()
        KeyAttestationDetector.resetForTest() // idempotent
    }
}
