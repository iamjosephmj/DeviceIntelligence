package io.ssemaj.deviceintelligence

import io.ssemaj.deviceintelligence.internal.TelemetryJson
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wire-format contract for the `remote_interaction` block in the
 * JSON output. Phase 1 ships only the rollup fields
 * (`event_counts`, `highest_severity_observed`) — detector-populated
 * fields (`enabled_a11y_services` etc.) remain empty arrays/null
 * until subsequent phases populate them.
 *
 * Backends that need to begin consuming the new block in Phase 1
 * see a stable empty shape; new keys are only added by future
 * phases.
 */
class RemoteInteractionFindingsCodecTest {

    @Test
    fun `EMPTY snapshot encodes with the documented baseline keys`() {
        val findings = RemoteInteractionFindings.EMPTY
        val json = TelemetryJson.encodeRemoteInteraction(findings)
        // Stable shape contract — exact key names matter to backends.
        assertTrue(""""event_counts":{}""" in json)
        assertTrue(""""highest_severity_observed":"INFO"""" in json)
        assertTrue(""""enabled_a11y_services":[]""" in json)
        assertTrue(""""screen_capture_active":false""" in json)
    }

    @Test
    fun `non-empty event counts encode with sorted keys`() {
        // Key sorting matters because TelemetryJson encodes deterministically
        // — backends diff snapshots field-by-field and unstable ordering
        // would create spurious diffs.
        val findings = RemoteInteractionFindings.EMPTY.copy(
            eventCounts = mapOf(
                InteractionEventKind.SCREEN_CAPTURE_STARTED to 1,
                InteractionEventKind.A11Y_SERVICE_ENABLED to 3,
            ),
            highestSeverityObserved = InteractionSeverity.HIGH,
        )
        val json = TelemetryJson.encodeRemoteInteraction(findings)
        val a11yIdx = json.indexOf("A11Y_SERVICE_ENABLED")
        val screenIdx = json.indexOf("SCREEN_CAPTURE_STARTED")
        assertTrue("expected A11Y before SCREEN in sorted output: $json",
            a11yIdx in 0..<screenIdx)
        assertTrue(""""highest_severity_observed":"HIGH"""" in json)
    }
}
