package io.ssemaj.deviceintelligence

import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Verifies that `SessionFindingsAggregator` folds the current
 * `RemoteInteractionAggregator.snapshot()` into the
 * `SessionFindings.remoteInteraction` field on every rollup.
 *
 * This is the integration seam between Phase 1 (aggregator) and
 * the existing session-rollup machinery. Without it, the
 * `remoteInteraction` field would always be EMPTY at runtime even
 * after detectors begin emitting in Phase 2.
 */
class SessionFindingsAggregatorSnapshotTest {

    // Reuse the same stub helpers as SessionFindingsTest.
    private fun stubReport(
        collectedAtEpochMs: Long,
        detectors: List<DetectorReport>,
    ): TelemetryReport = TelemetryReport(
        schemaVersion = TELEMETRY_SCHEMA_VERSION,
        libraryVersion = "test",
        collectedAtEpochMs = collectedAtEpochMs,
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
        detectors = detectors,
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
    fun `rollup carries the current aggregator snapshot into SessionFindings`() {
        val interaction = RemoteInteractionAggregator.forTesting()
        interaction.emit(InteractionEvent.A11yServiceEnabled(
            packageName = "com.example",
            serviceName = "com.example/.S",
            capabilities = emptySet(),
            installerPackage = null,
            firstInstallMs = 0L,
            severity = InteractionSeverity.HIGH,
            timestampMs = 1L,
            source = InteractionSource.SNAPSHOT,
        ))

        val sessionAgg = SessionFindingsAggregator(
            sessionStartedAtEpochMs = 1000L,
            remoteInteractionAggregator = interaction,
        )

        val findings: SessionFindings = sessionAgg.ingest(stubReport(2000L, emptyList()))

        assertEquals(InteractionSeverity.HIGH, findings.remoteInteraction.highestSeverityObserved)
        assertEquals(1, findings.remoteInteraction.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }

    @Test
    fun `remoteInteraction snapshot updates across successive ingests`() {
        val interaction = RemoteInteractionAggregator.forTesting()
        val sessionAgg = SessionFindingsAggregator(
            sessionStartedAtEpochMs = 1000L,
            remoteInteractionAggregator = interaction,
        )

        // First ingest — no events yet, snapshot should reflect EMPTY counts.
        val first = sessionAgg.ingest(stubReport(2000L, emptyList()))
        assertEquals(InteractionSeverity.INFO, first.remoteInteraction.highestSeverityObserved)
        assertEquals(null, first.remoteInteraction.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])

        // Emit an event between ingests.
        interaction.emit(InteractionEvent.A11yServiceEnabled(
            packageName = "com.evil",
            serviceName = "com.evil/.S",
            capabilities = emptySet(),
            installerPackage = null,
            firstInstallMs = 0L,
            severity = InteractionSeverity.MEDIUM,
            timestampMs = 2500L,
            source = InteractionSource.SNAPSHOT,
        ))

        // Second ingest — snapshot must now reflect the new event.
        val second = sessionAgg.ingest(stubReport(3000L, emptyList()))
        assertEquals(InteractionSeverity.MEDIUM, second.remoteInteraction.highestSeverityObserved)
        assertEquals(1, second.remoteInteraction.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }

    @Test
    fun `default constructor produces EMPTY remoteInteraction when no events emitted`() {
        // Smoke-test: default-value path (production call site in
        // DeviceIntelligence.observeSessionFlow) must compile and
        // behave sanely — remoteInteraction stays EMPTY before any
        // detector emits.
        val sessionAgg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val findings = sessionAgg.ingest(stubReport(2000L, emptyList()))
        assertEquals(RemoteInteractionFindings.EMPTY, findings.remoteInteraction)
    }
}
