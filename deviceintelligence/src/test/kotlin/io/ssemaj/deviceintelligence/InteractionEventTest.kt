package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the sealed `InteractionEvent` hierarchy: one variant per
 * `InteractionEventKind`, every variant exposes the common
 * `severity` / `timestampMs` / `source` triple, and every variant
 * derives its `kind` correctly. This contract is consumed by the
 * aggregator (Phase 1), the JSON codec (Phase 1), and the
 * detector implementations (Phase 2+) — pinning it here lets
 * downstream tasks land without re-litigating the shape.
 */
class InteractionEventTest {

    @Test
    fun `A11yServiceEnabled exposes kind`() {
        val ev = InteractionEvent.A11yServiceEnabled(
            packageName = "com.example",
            serviceName = "com.example/.SomeService",
            capabilities = setOf(A11yCapability.PERFORM_GESTURES),
            installerPackage = "com.android.vending",
            firstInstallMs = 1_700_000_000_000,
            severity = InteractionSeverity.HIGH,
            timestampMs = 1_700_000_001_000,
            source = InteractionSource.SNAPSHOT,
        )
        assertEquals(InteractionEventKind.A11Y_SERVICE_ENABLED, ev.kind)
        assertEquals(InteractionSeverity.HIGH, ev.severity)
        assertEquals(1_700_000_001_000, ev.timestampMs)
        assertEquals(InteractionSource.SNAPSHOT, ev.source)
    }

    @Test
    fun `every InteractionEventKind has at least one constructable variant`() {
        // If a variant is added later without a corresponding kind
        // (or vice versa) this test surfaces the mismatch.
        val kinds = InteractionEventKind.values().toSet()
        val constructed = sampleOneOfEach().map { it.kind }.toSet()
        assertEquals(
            "Every InteractionEventKind must have one InteractionEvent variant; missing: ${kinds - constructed}",
            kinds,
            constructed,
        )
    }

    /**
     * Constructs one example of each variant. If a new variant is
     * added to the sealed hierarchy, add it here too.
     */
    private fun sampleOneOfEach(): List<InteractionEvent> = listOf(
        InteractionEvent.A11yServiceEnabled(
            "p", "p/.S", setOf(A11yCapability.PERFORM_GESTURES), null, 0L,
            InteractionSeverity.HIGH, 1L, InteractionSource.SNAPSHOT,
        ),
        InteractionEvent.A11yStateChanged(
            enabled = true,
            severity = InteractionSeverity.HIGH, timestampMs = 1L, source = InteractionSource.LISTENER,
        ),
        InteractionEvent.RemoteControlAppDetected(
            packageName = "p", matchStrategy = MatchStrategy.PACKAGE_NAME_ALLOWLIST,
            capabilityScore = 0, isSideloaded = false,
            severity = InteractionSeverity.MEDIUM, timestampMs = 1L, source = InteractionSource.SNAPSHOT,
        ),
        InteractionEvent.ScreenCaptureStarted(
            initiatedByHost = true,
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.LISTENER,
        ),
        InteractionEvent.InputDeviceAttached(
            deviceId = 0, name = "kbd", isVirtual = false, sources = 0,
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.LISTENER,
        ),
        InteractionEvent.SuspiciousInputDispatch(
            activityClass = "com.example.MainActivity", sourceFlags = 0, deviceIsVirtual = true,
            severity = InteractionSeverity.HIGH, timestampMs = 1L, source = InteractionSource.INSTRUMENTED,
        ),
        InteractionEvent.WindowObscured(
            activityClass = "com.example.MainActivity", partial = false,
            severity = InteractionSeverity.HIGH, timestampMs = 1L, source = InteractionSource.INSTRUMENTED,
        ),
        InteractionEvent.OverlayWindowAddedByHost(
            viewClass = "com.example.Overlay",
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.INSTRUMENTED,
        ),
        InteractionEvent.VpnActivated(
            ownerPackage = null,
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.LISTENER,
        ),
        InteractionEvent.NotificationListenerEnabled(
            packageName = "p",
            severity = InteractionSeverity.MEDIUM, timestampMs = 1L, source = InteractionSource.SNAPSHOT,
        ),
        InteractionEvent.DeviceAdminActive(
            packageName = "p", isDeviceOwner = false,
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.SNAPSHOT,
        ),
        InteractionEvent.DetectorFailed(
            detectorName = "X", reasonClass = "RuntimeException",
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.SNAPSHOT,
        ),
        InteractionEvent.RuntimeMismatch(
            pluginVersion = "1.2.0", runtimeVersion = "1.1.0",
            severity = InteractionSeverity.INFO, timestampMs = 1L, source = InteractionSource.INSTRUMENTED,
        ),
    )
}
