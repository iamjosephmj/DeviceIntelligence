package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Smoke tests for [BootloaderIntegrityDetector] structural invariants.
 *
 * The detector's full integration path (second AndroidKeyStore keygen,
 * X509 chain walks, signature verifications) is exercised end-to-end
 * by the sample app at `samples/minimal` against a real Android
 * runtime — it cannot run in pure JVM unit tests because
 * `AndroidKeyStore` is a device-side service.
 *
 * The cross-check logic itself has deep table-driven coverage in
 * [ChainValidatorTest]; the smoke tests here only assert the parts
 * that survive in a JVM-only test runner.
 */
class BootloaderIntegrityDetectorTest {

    @Test
    fun `detector id matches the F15 contract`() {
        // Stable identifier — backends key on this. Any change is a
        // wire-format break and would need a corresponding bump.
        assertEquals("F15.bootloader_integrity", BootloaderIntegrityDetector.id)
    }

    @Test
    fun `resetForTest does not throw before any evaluate call`() {
        // Callable from a fresh process state to make a TestRig-style
        // fixture deterministic. Must not assume the cache has been
        // populated yet.
        BootloaderIntegrityDetector.resetForTest()
        BootloaderIntegrityDetector.resetForTest() // idempotent
    }
}
