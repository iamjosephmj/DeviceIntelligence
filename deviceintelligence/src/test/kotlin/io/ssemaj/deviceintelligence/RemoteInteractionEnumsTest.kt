package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Locks the wire-shaped enum contracts for the remote-interaction
 * surface. Ordinal stability matters: backends that pivot on
 * enum.ordinal() (Kotlin/Java consumers reading TelemetryJson
 * before deserializing) break if we reshuffle values. New values
 * MUST be appended at the end.
 */
class RemoteInteractionEnumsTest {

    @Test
    fun `InteractionSeverity has exactly three tiers in tier order`() {
        assertEquals(
            listOf("INFO", "MEDIUM", "HIGH"),
            InteractionSeverity.values().map { it.name },
        )
    }

    @Test
    fun `InteractionSource enumerates the three documented data paths`() {
        assertEquals(
            listOf("SNAPSHOT", "LISTENER", "INSTRUMENTED"),
            InteractionSource.values().map { it.name },
        )
    }

    @Test
    fun `InteractionEventKind enumerates all 13 planned variants in append-only order`() {
        // Phase 1 ships the full enum so wire format is stable even
        // though detectors are not yet emitting all kinds. Ordered
        // comparison enforces the file's "append at the end" contract —
        // new values MUST be added at the end, never inserted.
        assertEquals(
            listOf(
                "A11Y_SERVICE_ENABLED",
                "A11Y_STATE_CHANGED",
                "REMOTE_CONTROL_APP_DETECTED",
                "SCREEN_CAPTURE_STARTED",
                "INPUT_DEVICE_ATTACHED",
                "SUSPICIOUS_INPUT_DISPATCH",
                "WINDOW_OBSCURED",
                "OVERLAY_WINDOW_ADDED_BY_HOST",
                "VPN_ACTIVATED",
                "NOTIFICATION_LISTENER_ENABLED",
                "DEVICE_ADMIN_ACTIVE",
                "DETECTOR_FAILED",
                "RUNTIME_MISMATCH",
            ),
            InteractionEventKind.values().map { it.name },
        )
    }

    @Test
    fun `MatchStrategy lists the four detection paths`() {
        assertEquals(
            listOf(
                "PACKAGE_NAME_ALLOWLIST",
                "SIGNING_CERT_ALLOWLIST",
                "CAPABILITY_PROFILE",
                "BEHAVIORAL_COMPOSITE",
            ),
            MatchStrategy.values().map { it.name },
        )
    }

    @Test
    fun `A11yCapability lists the four capabilities checked by A11yAbuseDetector`() {
        // The Phase 2 detector maps from AccessibilityServiceInfo.capabilities
        // bits into this enum. Ordered comparison enforces the file's "append
        // at the end" contract: new capabilities MUST be added at the end so
        // existing consumers' ordinal-based pivots do not shift.
        assertEquals(
            listOf(
                "RETRIEVE_WINDOW_CONTENT",
                "PERFORM_GESTURES",
                "FILTER_KEY_EVENTS",
                "TOUCH_EXPLORATION",
            ),
            A11yCapability.values().map { it.name },
        )
    }
}
