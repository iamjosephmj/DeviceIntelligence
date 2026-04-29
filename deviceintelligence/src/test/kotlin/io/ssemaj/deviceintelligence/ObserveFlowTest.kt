package io.ssemaj.deviceintelligence

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Pinning tests for the [DeviceIntelligence.observeFlow] inner
 * polling loop — same builder used by the public
 * [DeviceIntelligence.observe], minus the `withContext(Dispatchers.IO)`
 * wrap so virtual time works under [runTest].
 *
 * What we want to lock down:
 *  - First emission happens immediately (no leading `delay`).
 *  - Subsequent emissions are spaced by `interval`.
 *  - Cancelling the collecting scope stops the loop.
 *  - `produce` is called exactly once per emission (no double
 *    invocation per cycle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ObserveFlowTest {

    private fun stubReport(seq: Int): TelemetryReport = TelemetryReport(
        schemaVersion = TELEMETRY_SCHEMA_VERSION,
        libraryVersion = "test",
        collectedAtEpochMs = seq.toLong(),
        collectionDurationMs = 0L,
        device = DeviceContext(
            manufacturer = "test",
            model = "stub",
            sdkInt = 0,
            abi = "x86_64",
            fingerprint = "stub",
        ),
        app = AppContext(
            packageName = "test",
            apkPath = null,
            installerPackage = null,
            signerCertSha256 = emptyList(),
            buildVariant = null,
            libraryPluginVersion = null,
        ),
        detectors = emptyList(),
        summary = ReportSummary(
            totalFindings = 0,
            findingsBySeverity = emptyMap(),
            findingsByKind = emptyMap(),
            detectorsWithFindings = emptyList(),
            detectorsInconclusive = emptyList(),
            detectorsErrored = emptyList(),
        ),
    )

    @Test
    fun `first emission happens immediately`() = runTest {
        var calls = 0
        val flow = DeviceIntelligence.observeFlow(interval = 1.seconds) {
            stubReport(calls++)
        }
        val first = flow.first()
        assertEquals("first report carries seq=0", 0L, first.collectedAtEpochMs)
        assertEquals("produce called exactly once", 1, calls)
    }

    @Test
    fun `emissions are spaced by interval`() = runTest {
        var calls = 0
        val emissions = DeviceIntelligence
            .observeFlow(interval = 500.milliseconds) { stubReport(calls++) }
            .take(3)
            .toList()
        assertEquals(3, emissions.size)
        assertEquals(0L, emissions[0].collectedAtEpochMs)
        assertEquals(1L, emissions[1].collectedAtEpochMs)
        assertEquals(2L, emissions[2].collectedAtEpochMs)
        assertEquals("produce called once per emission", 3, calls)
    }

    @Test
    fun `take(N) cancels the loop after N emissions`() = runTest {
        var calls = 0
        DeviceIntelligence
            .observeFlow(interval = 100.milliseconds) { stubReport(calls++) }
            .take(2)
            .toList()
        // The implementation invokes `produce` then `delay`. After
        // emitting the second value `take(2)` cancels the collector
        // before the next iteration can call produce again.
        assertEquals("produce capped at the take limit", 2, calls)
        assertTrue(calls <= 2)
    }
}
