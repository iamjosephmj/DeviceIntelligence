package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.CollectOptions
import io.ssemaj.deviceintelligence.DetectorReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [TelemetryCollector.filterDetectors] — the
 * [CollectOptions] semantics in isolation. Doesn't spin up a real
 * Context (so doesn't need Robolectric); exercises the filter
 * function directly with synthetic detectors.
 *
 * What we want to pin:
 *  - `CollectOptions.DEFAULT` keeps every detector, in registered
 *    order.
 *  - `skip` removes the named detectors but preserves the order
 *    of the rest.
 *  - `only` keeps just the named detectors, again in registered
 *    order (NOT in `only`'s iteration order — the detector list
 *    has ordering dependencies, e.g. `attestation.key` must run
 *    before `integrity.bootloader`).
 *  - `only` overrides `skip` when both are set (documented in the
 *    [CollectOptions] kdoc).
 *  - Empty `only` means no detectors run.
 *  - Filtering an unknown id is a no-op (skipping
 *    "integrity.nonexistent" doesn't error).
 */
class TelemetryCollectorFilterTest {

    /** Tiny stub matching the internal [Detector] interface — only [id] is read by [TelemetryCollector.filterDetectors]. */
    private class StubDetector(override val id: String) : Detector {
        override fun evaluate(ctx: DetectorContext): DetectorReport =
            ok(id, emptyList(), 0L)
    }

    private val detectors: List<Detector> = listOf(
        StubDetector("integrity.apk"),
        StubDetector("runtime.emulator"),
        StubDetector("runtime.cloner"),
        StubDetector("attestation.key"),
        StubDetector("integrity.bootloader"),
        StubDetector("runtime.environment"),
        StubDetector("runtime.root"),
        StubDetector("integrity.art"),
    )

    private fun ids(filtered: List<Detector>): List<String> = filtered.map { it.id }

    @Test
    fun `default keeps everything in registered order`() {
        val out = TelemetryCollector.filterDetectors(detectors, CollectOptions.DEFAULT)
        assertEquals(detectors.map { it.id }, ids(out))
    }

    @Test
    fun `skip removes named detectors`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(skip = setOf("integrity.apk", "integrity.art")),
        )
        assertEquals(
            listOf(
                "runtime.emulator",
                "runtime.cloner",
                "attestation.key",
                "integrity.bootloader",
                "runtime.environment",
                "runtime.root",
            ),
            ids(out),
        )
    }

    @Test
    fun `only keeps named detectors in registered order`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(only = setOf("integrity.art", "attestation.key")),
        )
        assertEquals(
            listOf("attestation.key", "integrity.art"),
            ids(out),
        )
    }

    @Test
    fun `only overrides skip when both set`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(
                skip = setOf("integrity.art"),
                only = setOf("integrity.art", "runtime.root"),
            ),
        )
        assertEquals(listOf("runtime.root", "integrity.art"), ids(out))
    }

    @Test
    fun `empty only set runs nothing`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(only = emptySet()),
        )
        assertTrue("expected no detectors when only=emptySet()", out.isEmpty())
    }

    @Test
    fun `skipping an unknown id is a no-op`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(skip = setOf("integrity.does-not-exist")),
        )
        assertEquals(detectors.map { it.id }, ids(out))
    }

    @Test
    fun `only with an unknown id ignores it`() {
        val out = TelemetryCollector.filterDetectors(
            detectors,
            CollectOptions(only = setOf("integrity.art", "runtime.does-not-exist")),
        )
        assertEquals(listOf("integrity.art"), ids(out))
    }
}
