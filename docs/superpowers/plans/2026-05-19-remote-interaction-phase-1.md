# RemoteInteraction Detector Family — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay the foundational types, aggregator, public API, and `IntegritySignal` extension that all subsequent phases depend on. No detectors fire yet; no listeners are attached; no bytecode is rewritten. End state: a consumer can subscribe to `DeviceIntelligence.interactionEvents`, get an empty flow (no detector populates it yet), and see an empty `SessionFindings.remoteInteraction` populated on every report.

**Architecture:** A new `RemoteInteractionAggregator` (process singleton on `LibraryScope`) collects `InteractionEvent`s via a `MutableSharedFlow` (replay 16, buffer 64, DROP_OLDEST). Snapshots fold into a new `RemoteInteractionFindings` field on `SessionFindings`. Three new `IntegritySignal` values surface high/medium/info severity buckets via the existing `IntegritySignalMapper`. The aggregator is created by `DeviceIntelligenceInitProvider`, exposed as `DeviceIntelligence.interactionEvents`, and snapshotted by `SessionFindingsAggregator`.

**Tech Stack:** Kotlin 2.x, kotlinx.coroutines (`SharedFlow`, `LibraryScope`), JUnit 4, kotlinx-coroutines-test, existing `:deviceintelligence` Android library module.

---

## Spec reference

Implements §6.1, §6.3, §6.4, §6.5 (foundation only), §8.2, §8.3, §8.5 of `docs/superpowers/specs/2026-05-19-remote-interaction-detector-design.md`.

**Out of scope for Phase 1** (each gets its own plan later):
- Phase 2 (1.3.0): Snapshot detectors (A11y, RAT-package, input source, overlay, context) + allowlist asset
- Phase 3 (1.4.0): Listener attachment + `RemoteInteractionInitProvider`
- Phase 4 (1.5.0): Capability-profile strategy + `QUERY_ALL_PACKAGES` opt-in + behavioral modifiers
- Phase 5 (1.6.0): AGP `AsmClassVisitorFactory` instrumentation + `RemoteInteractionRuntime`
- Phase 6 (1.7.0): Sample app additions + macrobenchmark + Flag 6 CTF artifacts

---

## File structure

**Created in Phase 1:**

| File | Responsibility |
|---|---|
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt` | Public API: `InteractionEvent` sealed interface, `InteractionSeverity` / `InteractionSource` / `InteractionEventKind` / `A11yCapability` / `MatchStrategy` enums |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindings.kt` | Public API: snapshot data classes (`RemoteInteractionFindings`, `A11yServiceSummary`, `RemoteControlPackageSummary`, `CapabilityProfileMatch`, `InputDeviceSummary`) |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregator.kt` | Internal: process-singleton aggregator with `MutableSharedFlow`, atomic counters, snapshot folding |
| `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventTest.kt` | JVM unit test for sealed-hierarchy contract + `kind` derivation |
| `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt` | JVM unit test for emit ordering, severity bump, snapshot folding, DROP_OLDEST flood, concurrent emit |
| `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsCodecTest.kt` | Wire-format contract test for the new TelemetryJson surface |

**Modified in Phase 1:**

| File | Change |
|---|---|
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt` | Append 3 new enum values + extend `IntegritySignalMapper` mapping table |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindings.kt` | Add `remoteInteraction: RemoteInteractionFindings` field to `SessionFindings` data class |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregator.kt` | Pull `aggregator.snapshot()` into new field on every rollup |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/DeviceIntelligence.kt` | Add `public val interactionEvents: SharedFlow<InteractionEvent>` delegating to `RemoteInteractionAggregator.events` |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/DeviceIntelligenceInitProvider.kt` | Construct the `RemoteInteractionAggregator` singleton at boot |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/TelemetryJson.kt` | Encode `SessionFindings.remoteInteraction` block |
| `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsTest.kt` | Cover new `remoteInteraction` field default value |
| `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt` | Cover new finding-kind → signal mappings |
| `CHANGELOG.md` | Add 1.2.0-alpha01 entry |
| `gradle.properties` | Bump `VERSION_NAME` to `1.2.0-alpha01` |

---

## Conventions used in this plan

- **Test framework:** JUnit 4 (`org.junit.Test`, `org.junit.Assert.*`). Coroutines tests use `kotlinx.coroutines.test.runTest`.
- **File header docs:** Every new top-level Kotlin file starts with a KDoc block explaining *why* this file exists, matching the project's existing pattern (see `IntegrityVerdict.kt`, `LibraryScope.kt`).
- **Commit message style:** Imperative `feat:` / `test:` / `docs:` prefix, ≤72-char subject, matches recent history (`feat: 1.x detector additions`, `docs: CHANGELOG.md, SECURITY.md, README + CTF roadmap polish for 1.0`).
- **Branch:** Work directly on `main` per the project's existing single-trunk workflow. Each task ends with a commit; no separate feature branch.

---

## Task 1: Add foundational enums

**Files:**
- Create: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionEnumsTest.kt`

- [ ] **Step 1: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionEnumsTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
    fun `InteractionEventKind has one entry per planned event variant`() {
        // Phase 1 ships the full enum so wire format is stable
        // even though detectors are not yet emitting all kinds.
        val expected = setOf(
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
        )
        assertEquals(expected, InteractionEventKind.values().map { it.name }.toSet())
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
    fun `A11yCapability includes the four capabilities checked by A11yAbuseDetector`() {
        // The detector (Phase 2) maps from AccessibilityServiceInfo.capabilities
        // bits into this enum. Keeping the names locked here means the
        // Phase 2 detector can land without renaming.
        val required = setOf(
            "RETRIEVE_WINDOW_CONTENT",
            "PERFORM_GESTURES",
            "FILTER_KEY_EVENTS",
            "TOUCH_EXPLORATION",
        )
        assertTrue(
            "A11yCapability missing required entries; have: ${A11yCapability.values().map { it.name }}",
            A11yCapability.values().map { it.name }.toSet().containsAll(required),
        )
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionEnumsTest"
```

Expected: compilation failure — `InteractionSeverity`, `InteractionSource`, `InteractionEventKind`, `MatchStrategy`, `A11yCapability` are unresolved references.

- [ ] **Step 3: Create the implementation file**

Create `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt`:

```kotlin
package io.ssemaj.deviceintelligence

/**
 * Public types for the RemoteInteraction detector family — the
 * SDK surface that exposes accessibility-service abuse,
 * remote-control app presence, screen-capture activity,
 * input-source anomalies, and overlay/tapjacking conditions.
 *
 * Phase 1 (this file) declares the enums + sealed event hierarchy.
 * Detectors (Phase 2), listeners (Phase 3), capability-profile
 * scoring (Phase 4), and compile-time instrumentation (Phase 5)
 * populate the events; consumers subscribe via
 * [DeviceIntelligence.interactionEvents].
 *
 * Enum ordinal stability: new values MUST be appended at the end.
 * Existing values must not be renamed (kind strings appear in
 * `TelemetryJson` wire output) or reordered (consumers may pivot
 * on `enum.ordinal()`).
 */

/**
 * Tiered severity for [InteractionEvent]s. The three tiers map
 * 1:1 onto [IntegritySignal.REMOTE_INTERACTION_HIGH_RISK] /
 * `_AMBIENT_RISK` / `_CONTEXT` via [IntegritySignalMapper].
 */
public enum class InteractionSeverity { INFO, MEDIUM, HIGH }

/**
 * Origin of an [InteractionEvent].
 *
 *  - [SNAPSHOT] — emitted by a one-shot snapshot detector during
 *    `PrewarmCoordinator.prewarm()`.
 *  - [LISTENER] — emitted by a system-callback listener attached
 *    by `RemoteInteractionInitProvider` for the session lifetime.
 *  - [INSTRUMENTED] — emitted by compile-time bytecode hooks
 *    injected into the host app's Activity dispatch / framework
 *    call sites by the AGP plugin.
 *
 * Backends use this to weight event provenance differently (e.g.
 * a snapshot finding is "true at session start"; an instrumented
 * finding is "true at THIS moment").
 */
public enum class InteractionSource { SNAPSHOT, LISTENER, INSTRUMENTED }

/**
 * Discriminator for [InteractionEvent] variants. One value per
 * sealed subclass; used for keying rolling counts in
 * [io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator]
 * and as the suffix of `remote_interaction.*` finding kinds in
 * `TelemetryJson`.
 */
public enum class InteractionEventKind {
    A11Y_SERVICE_ENABLED,
    A11Y_STATE_CHANGED,
    REMOTE_CONTROL_APP_DETECTED,
    SCREEN_CAPTURE_STARTED,
    INPUT_DEVICE_ATTACHED,
    SUSPICIOUS_INPUT_DISPATCH,
    WINDOW_OBSCURED,
    OVERLAY_WINDOW_ADDED_BY_HOST,
    VPN_ACTIVATED,
    NOTIFICATION_LISTENER_ENABLED,
    DEVICE_ADMIN_ACTIVE,
    DETECTOR_FAILED,
    RUNTIME_MISMATCH,
}

/**
 * How a `RemoteControlAppDetected` event was matched. The two
 * allowlist strategies require the package list bundled in
 * `assets/io.ssemaj.deviceintelligence/remote_packages.json`
 * (added in Phase 2). The capability strategies are name-agnostic
 * and detect TeamViewer-class apps even when not in the allowlist
 * (added in Phase 4).
 */
public enum class MatchStrategy {
    PACKAGE_NAME_ALLOWLIST,
    SIGNING_CERT_ALLOWLIST,
    CAPABILITY_PROFILE,
    BEHAVIORAL_COMPOSITE,
}

/**
 * Mirror of `AccessibilityServiceInfo.capabilities` bits as a
 * Kotlin-typed set. The Phase 2 `A11yAbuseDetector` populates
 * this from `AccessibilityServiceInfo.getCapabilities()`.
 */
public enum class A11yCapability {
    RETRIEVE_WINDOW_CONTENT,
    PERFORM_GESTURES,
    FILTER_KEY_EVENTS,
    TOUCH_EXPLORATION,
}
```

- [ ] **Step 4: Run test to verify it passes**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionEnumsTest"
```

Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionEnumsTest.kt
git commit -m "feat(interaction): foundational enums for RemoteInteraction family"
```

---

## Task 2: Add `InteractionEvent` sealed hierarchy

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventTest.kt`

- [ ] **Step 1: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventTest.kt`:

```kotlin
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
```

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.InteractionEventTest"
```

Expected: compilation failure — `InteractionEvent` is unresolved.

- [ ] **Step 3: Append the sealed hierarchy to `RemoteInteraction.kt`**

Append the following to `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt`:

```kotlin

/**
 * A signal observed in the remote-interaction surface — emitted
 * either by a snapshot detector, a system listener, or a
 * compile-time-injected hook, and consumed via
 * [DeviceIntelligence.interactionEvents].
 *
 * Every variant carries the same three common fields:
 *  - [severity] — tier used by [IntegritySignalMapper] to decide
 *    which `REMOTE_INTERACTION_*` signal to surface.
 *  - [timestampMs] — `System.currentTimeMillis()` at emit time.
 *  - [source] — origin of the event (see [InteractionSource]).
 *
 * Variant-specific fields document each detector's evidence.
 * New variants must also be added to [InteractionEventKind] and
 * to `InteractionEventTest.sampleOneOfEach`.
 */
public sealed interface InteractionEvent {
    public val severity: InteractionSeverity
    public val timestampMs: Long
    public val source: InteractionSource

    /**
     * Discriminator for rolling counts and finding-kind suffixing.
     * Default implementation maps each sealed subtype to its
     * canonical [InteractionEventKind]; subclasses must not
     * override.
     */
    public val kind: InteractionEventKind
        get() = when (this) {
            is A11yServiceEnabled            -> InteractionEventKind.A11Y_SERVICE_ENABLED
            is A11yStateChanged              -> InteractionEventKind.A11Y_STATE_CHANGED
            is RemoteControlAppDetected      -> InteractionEventKind.REMOTE_CONTROL_APP_DETECTED
            is ScreenCaptureStarted          -> InteractionEventKind.SCREEN_CAPTURE_STARTED
            is InputDeviceAttached           -> InteractionEventKind.INPUT_DEVICE_ATTACHED
            is SuspiciousInputDispatch       -> InteractionEventKind.SUSPICIOUS_INPUT_DISPATCH
            is WindowObscured                -> InteractionEventKind.WINDOW_OBSCURED
            is OverlayWindowAddedByHost      -> InteractionEventKind.OVERLAY_WINDOW_ADDED_BY_HOST
            is VpnActivated                  -> InteractionEventKind.VPN_ACTIVATED
            is NotificationListenerEnabled   -> InteractionEventKind.NOTIFICATION_LISTENER_ENABLED
            is DeviceAdminActive             -> InteractionEventKind.DEVICE_ADMIN_ACTIVE
            is DetectorFailed                -> InteractionEventKind.DETECTOR_FAILED
            is RuntimeMismatch               -> InteractionEventKind.RUNTIME_MISMATCH
        }

    public data class A11yServiceEnabled(
        val packageName: String,
        val serviceName: String,
        val capabilities: Set<A11yCapability>,
        val installerPackage: String?,
        val firstInstallMs: Long,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class A11yStateChanged(
        val enabled: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class RemoteControlAppDetected(
        val packageName: String,
        val matchStrategy: MatchStrategy,
        val capabilityScore: Int,
        val isSideloaded: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class ScreenCaptureStarted(
        val initiatedByHost: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class InputDeviceAttached(
        val deviceId: Int,
        val name: String,
        val isVirtual: Boolean,
        val sources: Int,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class SuspiciousInputDispatch(
        val activityClass: String,
        val sourceFlags: Int,
        val deviceIsVirtual: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class WindowObscured(
        val activityClass: String,
        val partial: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class OverlayWindowAddedByHost(
        val viewClass: String,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class VpnActivated(
        val ownerPackage: String?,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class NotificationListenerEnabled(
        val packageName: String,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class DeviceAdminActive(
        val packageName: String,
        val isDeviceOwner: Boolean,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class DetectorFailed(
        val detectorName: String,
        val reasonClass: String,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent

    public data class RuntimeMismatch(
        val pluginVersion: String,
        val runtimeVersion: String,
        override val severity: InteractionSeverity,
        override val timestampMs: Long,
        override val source: InteractionSource,
    ) : InteractionEvent
}
```

- [ ] **Step 4: Run test to verify it passes**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.InteractionEventTest"
```

Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteraction.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventTest.kt
git commit -m "feat(interaction): InteractionEvent sealed hierarchy"
```

---

## Task 3: Add `RemoteInteractionFindings` snapshot types

**Files:**
- Create: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindings.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsTest.kt`

- [ ] **Step 1: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the snapshot data shape exposed on
 * [SessionFindings.remoteInteraction]. Phase 1 ships only the
 * default/empty shape; subsequent phases populate fields.
 */
class RemoteInteractionFindingsTest {

    @Test
    fun `EMPTY snapshot has all collections empty and INFO highest severity`() {
        val empty = RemoteInteractionFindings.EMPTY
        assertTrue(empty.enabledA11yServices.isEmpty())
        assertTrue(empty.remoteControlPackages.isEmpty())
        assertTrue(empty.capabilityProfileMatches.isEmpty())
        assertTrue(empty.externalInputDevices.isEmpty())
        assertTrue(empty.overlayCapablePackages.isEmpty())
        assertTrue(empty.notificationListenerPackages.isEmpty())
        assertTrue(empty.activeDeviceAdmins.isEmpty())
        assertNull(empty.activeVpnOwnerPackage)
        assertFalse(empty.screenCaptureActive)
        assertNull(empty.screenCaptureActiveSince)
        assertTrue(empty.eventCounts.isEmpty())
        assertEquals(InteractionSeverity.INFO, empty.highestSeverityObserved)
    }

    @Test
    fun `EMPTY snapshot is a single shared instance`() {
        // Hot-path callers (every SessionFindings rollup) read EMPTY.
        // Allocating on every read would be wasteful.
        assertTrue(RemoteInteractionFindings.EMPTY === RemoteInteractionFindings.EMPTY)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionFindingsTest"
```

Expected: compilation failure — `RemoteInteractionFindings` is unresolved.

- [ ] **Step 3: Create the snapshot file**

Create `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindings.kt`:

```kotlin
package io.ssemaj.deviceintelligence

/**
 * Snapshot of remote-interaction state at the moment
 * [SessionFindings] was assembled. Populated by
 * `RemoteInteractionAggregator.snapshot()` and embedded in
 * [SessionFindings.remoteInteraction].
 *
 * Phase 1 ships only the data shape and the [EMPTY] sentinel.
 * Subsequent phases populate fields:
 *  - Phase 2 snapshot detectors → [enabledA11yServices],
 *    [remoteControlPackages], [externalInputDevices],
 *    [overlayCapablePackages], [notificationListenerPackages],
 *    [activeDeviceAdmins].
 *  - Phase 3 listeners → [activeVpnOwnerPackage],
 *    [screenCaptureActive], [screenCaptureActiveSince].
 *  - Phase 4 capability scorer → [capabilityProfileMatches].
 *
 * [eventCounts] and [highestSeverityObserved] are aggregator-managed
 * rollups available from Phase 1 onward (they remain at default
 * values until detectors begin emitting).
 */
public data class RemoteInteractionFindings(
    public val enabledA11yServices: List<A11yServiceSummary>,
    public val remoteControlPackages: List<RemoteControlPackageSummary>,
    public val capabilityProfileMatches: List<CapabilityProfileMatch>,
    public val externalInputDevices: List<InputDeviceSummary>,
    public val overlayCapablePackages: List<String>,
    public val notificationListenerPackages: List<String>,
    public val activeDeviceAdmins: List<String>,
    public val activeVpnOwnerPackage: String?,
    public val screenCaptureActive: Boolean,
    public val screenCaptureActiveSince: Long?,
    public val eventCounts: Map<InteractionEventKind, Int>,
    public val highestSeverityObserved: InteractionSeverity,
) {
    public companion object {
        /** Shared empty snapshot; safe to return from any thread. */
        public val EMPTY: RemoteInteractionFindings = RemoteInteractionFindings(
            enabledA11yServices = emptyList(),
            remoteControlPackages = emptyList(),
            capabilityProfileMatches = emptyList(),
            externalInputDevices = emptyList(),
            overlayCapablePackages = emptyList(),
            notificationListenerPackages = emptyList(),
            activeDeviceAdmins = emptyList(),
            activeVpnOwnerPackage = null,
            screenCaptureActive = false,
            screenCaptureActiveSince = null,
            eventCounts = emptyMap(),
            highestSeverityObserved = InteractionSeverity.INFO,
        )
    }
}

public data class A11yServiceSummary(
    public val packageName: String,
    public val serviceName: String,
    public val capabilities: Set<A11yCapability>,
    public val installerPackage: String?,
    public val isAllowlisted: Boolean,
)

public data class RemoteControlPackageSummary(
    public val packageName: String,
    public val matchStrategy: MatchStrategy,
    public val severity: InteractionSeverity,
)

public data class CapabilityProfileMatch(
    public val packageName: String,
    public val capabilityScore: Int,
    public val isSideloaded: Boolean,
    public val isDebugSigned: Boolean,
)

public data class InputDeviceSummary(
    public val deviceId: Int,
    public val name: String,
    public val isVirtual: Boolean,
    public val sources: Int,
)
```

- [ ] **Step 4: Run test to verify it passes**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionFindingsTest"
```

Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindings.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsTest.kt
git commit -m "feat(interaction): RemoteInteractionFindings snapshot data shape"
```

---

## Task 4: Add `RemoteInteractionAggregator` skeleton + basic emit tests

**Files:**
- Create: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregator.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt`

- [ ] **Step 1: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence.internal.interaction

import io.ssemaj.deviceintelligence.InteractionEvent
import io.ssemaj.deviceintelligence.InteractionEventKind
import io.ssemaj.deviceintelligence.InteractionSeverity
import io.ssemaj.deviceintelligence.InteractionSource
import io.ssemaj.deviceintelligence.MatchStrategy
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Aggregator contract pinned: emit ordering, rolling counts,
 * severity bump, snapshot folding, and SharedFlow replay semantics.
 *
 * No detectors emit in Phase 1; this test feeds events directly
 * via the internal `emit()` entry to validate the aggregator's
 * behavior independently.
 */
class RemoteInteractionAggregatorTest {

    @Test
    fun `freshly constructed aggregator has empty snapshot`() {
        val agg = RemoteInteractionAggregator.forTesting()
        val snap = agg.snapshot()
        assertEquals(emptyMap<InteractionEventKind, Int>(), snap.eventCounts)
        assertEquals(InteractionSeverity.INFO, snap.highestSeverityObserved)
    }

    @Test
    fun `emit increments per-kind count`() {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        val snap = agg.snapshot()
        assertEquals(3, snap.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }

    @Test
    fun `highest severity observed monotonically increases`() {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        assertEquals(InteractionSeverity.INFO, agg.snapshot().highestSeverityObserved)
        agg.emit(sampleEvent(InteractionSeverity.MEDIUM))
        assertEquals(InteractionSeverity.MEDIUM, agg.snapshot().highestSeverityObserved)
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        assertEquals(InteractionSeverity.HIGH, agg.snapshot().highestSeverityObserved)
        // INFO after HIGH must NOT drop the high-water mark
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        assertEquals(InteractionSeverity.HIGH, agg.snapshot().highestSeverityObserved)
    }

    @Test
    fun `emitted events flow through SharedFlow in order`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        val first = sampleEvent(InteractionSeverity.INFO, timestampMs = 100L)
        val second = sampleEvent(InteractionSeverity.HIGH, timestampMs = 200L)
        agg.emit(first)
        agg.emit(second)
        // Replay buffer of 16 means late collectors see the prior events.
        val collected = agg.events.take(2).toList()
        assertEquals(listOf(first, second), collected)
    }

    @Test
    fun `events SharedFlow replays last events to new collectors`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        // Subscribing AFTER emit: replay should deliver the missed event.
        val ev = agg.events.first()
        assertNotNull(ev)
        assertEquals(InteractionSeverity.HIGH, ev.severity)
    }

    private fun sampleEvent(
        severity: InteractionSeverity,
        timestampMs: Long = 1L,
    ): InteractionEvent = InteractionEvent.A11yServiceEnabled(
        packageName = "com.example",
        serviceName = "com.example/.S",
        capabilities = emptySet(),
        installerPackage = null,
        firstInstallMs = 0L,
        severity = severity,
        timestampMs = timestampMs,
        source = InteractionSource.SNAPSHOT,
    )
}
```

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregatorTest"
```

Expected: compilation failure — `RemoteInteractionAggregator` is unresolved.

- [ ] **Step 3: Create the aggregator implementation**

Create directory and file `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregator.kt`:

```kotlin
package io.ssemaj.deviceintelligence.internal.interaction

import io.ssemaj.deviceintelligence.InteractionEvent
import io.ssemaj.deviceintelligence.InteractionEventKind
import io.ssemaj.deviceintelligence.InteractionSeverity
import io.ssemaj.deviceintelligence.RemoteInteractionFindings
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-singleton sink for [InteractionEvent]s emitted by all
 * three data paths (snapshot detectors, system listeners,
 * bytecode-injected hooks). Constructed at boot by
 * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider]
 * and exposed on [io.ssemaj.deviceintelligence.DeviceIntelligence.interactionEvents].
 *
 * Thread-safety: every member is safe for concurrent access from
 * any thread. The hot path ([emit]) is allocation-free for the
 * accounting work (`AtomicInteger.incrementAndGet`,
 * `ConcurrentHashMap.computeIfAbsent`) and uses [MutableSharedFlow.tryEmit]
 * with [BufferOverflow.DROP_OLDEST] so emitters never suspend.
 *
 * Buffer sizing rationale:
 *  - replay = 16: a screen that subscribes mid-session sees the
 *    last ~16 events (typically enough to render a meaningful
 *    "what's happened in this session" timeline).
 *  - extraBufferCapacity = 64: tolerates short consumer stalls
 *    without dropping; bytecode-injected hot path can flush
 *    bursts (e.g. rapid touch sequence).
 *  - DROP_OLDEST: a wedged consumer never back-pressures the UI
 *    thread; the SDK silently loses the oldest unread events.
 */
internal class RemoteInteractionAggregator private constructor(
    replayCount: Int,
    bufferCapacity: Int,
) {
    private val _events = MutableSharedFlow<InteractionEvent>(
        replay = replayCount,
        extraBufferCapacity = bufferCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Hot stream of every event the aggregator has accepted.
     * Backed by a [MutableSharedFlow] with [BufferOverflow.DROP_OLDEST]
     * so subscribers cannot back-pressure emitters.
     */
    val events: SharedFlow<InteractionEvent> = _events.asSharedFlow()

    private val counts = ConcurrentHashMap<InteractionEventKind, AtomicInteger>()
    private val highestSeverity = AtomicReference(InteractionSeverity.INFO)

    /**
     * Records an event into the rolling state and emits it on the
     * shared flow. Non-suspending; safe to call from the UI thread.
     */
    fun emit(event: InteractionEvent) {
        counts.computeIfAbsent(event.kind) { AtomicInteger(0) }.incrementAndGet()
        bumpSeverity(event.severity)
        _events.tryEmit(event)
    }

    /**
     * Folds the rolling state into the public snapshot embedded in
     * [io.ssemaj.deviceintelligence.SessionFindings.remoteInteraction].
     * Phase 1: only `eventCounts` and `highestSeverityObserved` are
     * populated; remaining fields stay at [RemoteInteractionFindings.EMPTY]
     * defaults until detectors land in subsequent phases.
     */
    fun snapshot(): RemoteInteractionFindings {
        val countSnap: Map<InteractionEventKind, Int> = counts
            .mapValues { (_, v) -> v.get() }
            .filterValues { it > 0 }
        return RemoteInteractionFindings.EMPTY.copy(
            eventCounts = countSnap,
            highestSeverityObserved = highestSeverity.get(),
        )
    }

    private fun bumpSeverity(observed: InteractionSeverity) {
        while (true) {
            val current = highestSeverity.get()
            if (observed.ordinal <= current.ordinal) return
            if (highestSeverity.compareAndSet(current, observed)) return
        }
    }

    companion object {
        const val DEFAULT_REPLAY: Int = 16
        const val DEFAULT_BUFFER: Int = 64

        /** Production constructor — used by `DeviceIntelligenceInitProvider`. */
        fun newProductionInstance(): RemoteInteractionAggregator =
            RemoteInteractionAggregator(DEFAULT_REPLAY, DEFAULT_BUFFER)

        /** Test constructor — explicit smaller buffers for deterministic flood tests. */
        internal fun forTesting(
            replayCount: Int = DEFAULT_REPLAY,
            bufferCapacity: Int = DEFAULT_BUFFER,
        ): RemoteInteractionAggregator =
            RemoteInteractionAggregator(replayCount, bufferCapacity)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregatorTest"
```

Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregator.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt
git commit -m "feat(interaction): RemoteInteractionAggregator with SharedFlow + rolling counts"
```

---

## Task 5: Add concurrency + DROP_OLDEST flood tests for aggregator

**Files:**
- Modify: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt`

- [ ] **Step 1: Append concurrent-emit and DROP_OLDEST tests**

Append to `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt` (inside the class):

```kotlin

    @Test
    fun `concurrent emits from N threads produce deterministic count rollup`() {
        val agg = RemoteInteractionAggregator.forTesting()
        val threadCount = 16
        val perThread = 250
        val expectedTotal = threadCount * perThread

        val threads = (0 until threadCount).map {
            Thread {
                repeat(perThread) {
                    agg.emit(sampleEvent(InteractionSeverity.MEDIUM))
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val snap = agg.snapshot()
        // Every emit increments the count; aggregator must lose nothing.
        assertEquals(expectedTotal, snap.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
        // Severity reached at least MEDIUM.
        assertEquals(InteractionSeverity.MEDIUM, snap.highestSeverityObserved)
    }

    @Test
    fun `DROP_OLDEST means flood does not throw and counts still reflect every emit`() {
        // No collector subscribed — buffer fills, then drops oldest.
        // The accounting (counts + severity) must still be exact because
        // emit() updates counts BEFORE attempting tryEmit.
        val agg = RemoteInteractionAggregator.forTesting(replayCount = 2, bufferCapacity = 4)
        val emitCount = 10_000
        repeat(emitCount) {
            agg.emit(sampleEvent(InteractionSeverity.INFO))
        }
        assertEquals(emitCount, agg.snapshot().eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }
```

- [ ] **Step 2: Run all tests in the file to verify pass**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregatorTest"
```

Expected: PASS, 7 tests total.

- [ ] **Step 3: Commit**

```bash
git add deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/internal/interaction/RemoteInteractionAggregatorTest.kt
git commit -m "test(interaction): aggregator concurrent emit + DROP_OLDEST flood"
```

---

## Task 6: Add new `IntegritySignal` enum values

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt`
- Test: extends `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt`

- [ ] **Step 1: Write the failing test**

Append to `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt` (inside the class):

```kotlin

    @Test
    fun `IntegritySignal includes the three remote-interaction values appended at end`() {
        val values = IntegritySignal.values()
        // Append-at-end discipline: the three new values must occupy the
        // last three positions so existing consumers' ordinal-based pivots
        // do not shift.
        assertEquals(IntegritySignal.REMOTE_INTERACTION_HIGH_RISK, values[values.size - 3])
        assertEquals(IntegritySignal.REMOTE_INTERACTION_AMBIENT_RISK, values[values.size - 2])
        assertEquals(IntegritySignal.REMOTE_INTERACTION_CONTEXT, values[values.size - 1])
    }
```

If `IntegritySignalMapperTest` does not yet import `IntegritySignal`, add `import io.ssemaj.deviceintelligence.IntegritySignal` and `import org.junit.Assert.assertEquals` at the top of the file (skip if already imported).

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.IntegritySignalMapperTest.IntegritySignal includes the three remote-interaction values appended at end"
```

Expected: compilation failure — `REMOTE_INTERACTION_HIGH_RISK` unresolved.

- [ ] **Step 3: Append the three enum values to `IntegritySignal.kt`**

Open `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt`. Find the existing `HARDWARE_ATTESTED_USERSPACE_TAMPERED,` entry (the last enum value, around line 250). Replace it with:

```kotlin
    HARDWARE_ATTESTED_USERSPACE_TAMPERED,

    // ---- Remote interaction (1.2.0+) ------------------------------------

    /**
     * At least one HIGH-severity remote-interaction finding has been
     * observed during the session. Examples: a non-allowlisted
     * accessibility service with gesture-injection capability is
     * enabled; a capability-profile match indicates a remote-control
     * app is installed; a touch dispatch arrived from a virtual
     * InputDevice; screen capture by an unknown app is active.
     *
     * Treat as advisory — same posture as
     * [TEE_ATTESTATION_DEGRADED]. Backends correlating against
     * payment risk should weight this similarly to
     * [HOOKING_FRAMEWORK_DETECTED].
     *
     * Backed by every `remote_interaction.*` finding emitted at
     * [Severity.CRITICAL].
     */
    REMOTE_INTERACTION_HIGH_RISK,

    /**
     * At least one MEDIUM-severity remote-interaction finding.
     * Examples: a known remote-support tool (TeamViewer QuickSupport,
     * AnyDesk) is installed; a notification listener service from a
     * non-allowlisted package is enabled; a recently-installed
     * accessibility service. Does NOT on its own indicate compromise —
     * many enterprise / accessibility-using devices surface this.
     * Use as one factor among several in risk scoring.
     *
     * Backed by every `remote_interaction.*` finding emitted at
     * [Severity.WARN].
     */
    REMOTE_INTERACTION_AMBIENT_RISK,

    /**
     * Operational context only — never a compromise indicator.
     * Examples: TalkBack is enabled; an external hardware keyboard
     * is paired; a VPN is active; MDM is provisioned. Useful for
     * explaining other signals but never blocks. Backends should
     * NOT use this signal to gate user actions.
     *
     * Backed by every `remote_interaction.*` finding emitted at
     * [Severity.INFO].
     */
    REMOTE_INTERACTION_CONTEXT,
```

- [ ] **Step 4: Run the new test to verify it passes**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.IntegritySignalMapperTest"
```

Expected: PASS for the new test; existing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt
git commit -m "feat(signal): three REMOTE_INTERACTION IntegritySignal values"
```

---

## Task 7: Extend `IntegritySignalMapper` for `remote_interaction.*` finding kinds

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt` (extends the `IntegritySignalMapper` object inside)
- Test: extends `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt`

- [ ] **Step 1: Write the failing test**

Append to `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt` (inside the class). Add `import io.ssemaj.deviceintelligence.Finding` and `import io.ssemaj.deviceintelligence.Severity` if not present:

```kotlin

    @Test
    fun `remote_interaction CRITICAL finding maps to REMOTE_INTERACTION_HIGH_RISK`() {
        val finding = Finding(
            kind = "remote_interaction.a11y_high_capability_service",
            severity = Severity.CRITICAL,
            details = emptyMap(),
        )
        val signal = IntegritySignalMapper.signalFor(finding)
        assertEquals(IntegritySignal.REMOTE_INTERACTION_HIGH_RISK, signal)
    }

    @Test
    fun `remote_interaction WARN finding maps to REMOTE_INTERACTION_AMBIENT_RISK`() {
        val finding = Finding(
            kind = "remote_interaction.remote_control_app_known",
            severity = Severity.WARN,
            details = emptyMap(),
        )
        val signal = IntegritySignalMapper.signalFor(finding)
        assertEquals(IntegritySignal.REMOTE_INTERACTION_AMBIENT_RISK, signal)
    }

    @Test
    fun `remote_interaction INFO finding maps to REMOTE_INTERACTION_CONTEXT`() {
        val finding = Finding(
            kind = "remote_interaction.vpn_active",
            severity = Severity.INFO,
            details = emptyMap(),
        )
        val signal = IntegritySignalMapper.signalFor(finding)
        assertEquals(IntegritySignal.REMOTE_INTERACTION_CONTEXT, signal)
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.IntegritySignalMapperTest"
```

Expected: 3 new tests FAIL — either `signalFor` returns null or maps to a different signal.

- [ ] **Step 3: Open `IntegritySignal.kt` and inspect the existing mapper**

The `IntegritySignalMapper` object starts around line 308 in `IntegritySignal.kt`. Read its existing `signalFor(finding: Finding): IntegritySignal?` function (or the closest equivalent — the existing test imports tell you the exact symbol). Whatever the existing dispatch is (a `when` on `finding.kind` prefix, a map lookup, etc.), add a branch that:

1. Matches any `finding.kind` starting with `"remote_interaction."`.
2. Routes by `finding.severity`: `CRITICAL` → `REMOTE_INTERACTION_HIGH_RISK`; `WARN` → `REMOTE_INTERACTION_AMBIENT_RISK`; `INFO` → `REMOTE_INTERACTION_CONTEXT`.

The exact code shape depends on what's already there. Example, assuming the existing mapper uses a `when` block on `finding.kind`:

```kotlin
// Inside IntegritySignalMapper.signalFor(...)
when {
    // …existing branches…

    finding.kind.startsWith("remote_interaction.") -> when (finding.severity) {
        Severity.CRITICAL -> IntegritySignal.REMOTE_INTERACTION_HIGH_RISK
        Severity.WARN     -> IntegritySignal.REMOTE_INTERACTION_AMBIENT_RISK
        Severity.INFO     -> IntegritySignal.REMOTE_INTERACTION_CONTEXT
    }

    else -> null
}
```

If the existing mapper uses a different shape (e.g. a `Map<String, IntegritySignal>`), prefer extending that shape with the three discriminator entries rather than adding a parallel `when`. The key requirement: every `remote_interaction.*` kind at every severity must resolve to exactly one of the three new signals.

- [ ] **Step 4: Run all mapper tests to verify pass**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.IntegritySignalMapperTest"
```

Expected: PASS, all tests including 3 new ones.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/IntegritySignal.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/IntegritySignalMapperTest.kt
git commit -m "feat(signal): map remote_interaction.* findings to severity-tiered IntegritySignals"
```

---

## Task 8: Extend `SessionFindings` with `remoteInteraction` field

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindings.kt`
- Test: extends `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsTest.kt`

- [ ] **Step 1: Write the failing test**

Append to `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsTest.kt` (inside the class). Add `import io.ssemaj.deviceintelligence.RemoteInteractionFindings` if not present:

```kotlin

    @Test
    fun `SessionFindings exposes remoteInteraction field defaulting to EMPTY`() {
        // The aggregator (Phase 1) starts empty before any detector emits.
        // Existing call sites that constructed SessionFindings without
        // `remoteInteraction` should now default to RemoteInteractionFindings.EMPTY.
        val findings = makeMinimalSessionFindings()
        assertEquals(RemoteInteractionFindings.EMPTY, findings.remoteInteraction)
    }

    /**
     * Helper: constructs a SessionFindings with minimum-viable values.
     * If the existing test file already has a similar helper, reuse it
     * instead of duplicating.
     */
    private fun makeMinimalSessionFindings(): SessionFindings = SessionFindings(
        latestReport = makeEmptyTelemetryReport(),
        findings = emptyList(),
        collectionsObserved = 0,
        sessionStartedAtEpochMs = 0L,
        lastUpdatedAtEpochMs = 0L,
    )

    /**
     * Mirror of the test helper inside the project's existing
     * `TelemetryCollectorFilterTest` — copy that shape if it differs
     * from what is produced here at runtime.
     */
    private fun makeEmptyTelemetryReport(): TelemetryReport = TelemetryReport(
        schemaVersion = TELEMETRY_SCHEMA_VERSION,
        appContext = AppContext.empty(),
        deviceContext = DeviceContext.empty(),
        detectors = emptyList(),
        summary = ReportSummary.empty(),
    )
```

If the existing test file already has helpers for constructing `SessionFindings` / `TelemetryReport`, REUSE them instead of duplicating. The exact import set will reveal what's available — check `SessionFindingsTest.kt`'s existing top and reuse what's there.

- [ ] **Step 2: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.SessionFindingsTest"
```

Expected: compilation failure — `SessionFindings` constructor missing required parameter (or `remoteInteraction` is unresolved).

- [ ] **Step 3: Modify `SessionFindings.kt` to add the field**

Open `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindings.kt`. Find the `SessionFindings` `data class` declaration (around line 85). Add a new property at the end with a default value so existing call sites continue to compile:

```kotlin
public data class SessionFindings(
    public val latestReport: TelemetryReport,
    public val findings: List<TrackedFinding>,
    public val collectionsObserved: Int,
    public val sessionStartedAtEpochMs: Long,
    public val lastUpdatedAtEpochMs: Long,
    /**
     * Snapshot of remote-interaction state at the moment this
     * `SessionFindings` was assembled. Defaults to
     * [RemoteInteractionFindings.EMPTY] for backward compatibility
     * with consumers that constructed `SessionFindings` directly
     * before 1.2.0. Production callers (specifically
     * [SessionFindingsAggregator]) populate this from
     * `RemoteInteractionAggregator.snapshot()` (see Task 9).
     *
     * @since 1.2.0
     */
    public val remoteInteraction: RemoteInteractionFindings = RemoteInteractionFindings.EMPTY,
)
```

- [ ] **Step 4: Run tests to verify pass**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.SessionFindingsTest"
```

Expected: PASS for the new test; existing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindings.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsTest.kt
git commit -m "feat(findings): SessionFindings.remoteInteraction field (defaults to EMPTY)"
```

---

## Task 9: Wire aggregator through `SessionFindingsAggregator` snapshot rollup

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregator.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregatorSnapshotTest.kt`

- [ ] **Step 1: Inspect the existing `SessionFindingsAggregator`**

Read `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregator.kt` in full. Identify:

1. The constructor / dependencies it accepts.
2. The method that assembles a `SessionFindings` instance (likely `addReport(...)` or `snapshot(...)`).
3. Whether it is constructed inside `DeviceIntelligenceInitProvider` or somewhere else.

This task adds the aggregator as a constructor dependency (default value `RemoteInteractionAggregator.newProductionInstance()` for backward compatibility with existing tests that construct it directly).

- [ ] **Step 2: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregatorSnapshotTest.kt`:

```kotlin
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
            // Reuse the constructor shape the existing file uses; this is a
            // placeholder for whatever existing required deps exist. Inspect
            // the file before this step and supply real values.
            remoteInteractionAggregator = interaction,
        )
        // Drive a rollup using the public method (likely `addReport(...)`
        // or `snapshot(...)` — use whatever the existing file exposes).
        val findings = sessionAgg.snapshot()
        assertEquals(InteractionSeverity.HIGH, findings.remoteInteraction.highestSeverityObserved)
        assertEquals(1, findings.remoteInteraction.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }
}
```

Note the placeholder constructor call: the actual constructor signature must come from the existing `SessionFindingsAggregator.kt`. Read that file first and adjust the test call to match its real shape — same applies to which method drives a rollup.

- [ ] **Step 3: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.SessionFindingsAggregatorSnapshotTest"
```

Expected: compilation failure on `remoteInteractionAggregator =` (parameter doesn't exist yet).

- [ ] **Step 4: Modify `SessionFindingsAggregator.kt`**

Open the existing `SessionFindingsAggregator.kt`. Add `remoteInteractionAggregator: RemoteInteractionAggregator` as a constructor parameter, defaulted to `RemoteInteractionAggregator.newProductionInstance()` to keep existing call sites compiling. Inside the method that constructs a `SessionFindings` instance, set `remoteInteraction = remoteInteractionAggregator.snapshot()`. Add the corresponding import: `import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator`.

Sketch (the exact existing surrounding code may differ — preserve it):

```kotlin
public class SessionFindingsAggregator(
    // …existing dependencies kept as-is…
    private val remoteInteractionAggregator: RemoteInteractionAggregator =
        RemoteInteractionAggregator.newProductionInstance(),
) {
    // …existing fields/methods…

    public fun snapshot(): SessionFindings = SessionFindings(
        latestReport = /* existing */,
        findings = /* existing */,
        collectionsObserved = /* existing */,
        sessionStartedAtEpochMs = /* existing */,
        lastUpdatedAtEpochMs = /* existing */,
        remoteInteraction = remoteInteractionAggregator.snapshot(),
    )
}
```

If `SessionFindingsAggregator` is currently constructed elsewhere (e.g. inside `DeviceIntelligenceInitProvider`), the next task (Task 10) wires up the production instance — the default value in this task's signature keeps that call site working without immediate change.

- [ ] **Step 5: Run all related tests**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.SessionFindingsAggregatorSnapshotTest" \
                                              --tests "io.ssemaj.deviceintelligence.SessionFindingsTest"
```

Expected: PASS for both classes.

- [ ] **Step 6: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregator.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/SessionFindingsAggregatorSnapshotTest.kt
git commit -m "feat(findings): SessionFindingsAggregator folds RemoteInteractionAggregator snapshot"
```

---

## Task 10: Expose `DeviceIntelligence.interactionEvents` and wire production aggregator at boot

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/DeviceIntelligence.kt`
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/DeviceIntelligenceInitProvider.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventsPropertyTest.kt`

- [ ] **Step 1: Inspect `DeviceIntelligence.kt` and `DeviceIntelligenceInitProvider.kt`**

Read both files. Identify:

1. How `DeviceIntelligence` (an `object`) currently exposes mutable internal state to test code (likely an `@VisibleForTesting` setter or an internal var).
2. Where `DeviceIntelligenceInitProvider.onCreate` constructs runtime singletons. We need to construct the `RemoteInteractionAggregator` there, store it in a package-internal `var`/`val` accessible from `DeviceIntelligence`, and expose `events` as `interactionEvents`.

A common pattern in this codebase: an `internal` mutable backing property on `DeviceIntelligence`, set by `DeviceIntelligenceInitProvider`. Use the same pattern that the existing wiring uses (don't invent a new injection style).

- [ ] **Step 2: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventsPropertyTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence

import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Pins the public-API contract: `DeviceIntelligence.interactionEvents`
 * is a non-null `SharedFlow<InteractionEvent>` backed by the
 * process-singleton aggregator that `DeviceIntelligenceInitProvider`
 * constructs at boot.
 *
 * In a pure-JVM test the InitProvider's `onCreate` never runs, so
 * this test goes through the internal install hook to seed an
 * aggregator instance. Production seeding happens in
 * `DeviceIntelligenceInitProvider.onCreate`.
 */
class InteractionEventsPropertyTest {

    @Test
    fun `interactionEvents property is non-null after aggregator installed`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        DeviceIntelligence.installRemoteInteractionAggregator(agg)
        assertNotNull(DeviceIntelligence.interactionEvents)
    }

    @Test
    fun `events emitted on aggregator surface on DeviceIntelligence interactionEvents`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        DeviceIntelligence.installRemoteInteractionAggregator(agg)

        val event = InteractionEvent.A11yServiceEnabled(
            packageName = "com.example",
            serviceName = "com.example/.S",
            capabilities = emptySet(),
            installerPackage = null,
            firstInstallMs = 0L,
            severity = InteractionSeverity.HIGH,
            timestampMs = 99L,
            source = InteractionSource.SNAPSHOT,
        )
        agg.emit(event)

        // Replay buffer means first() returns the just-emitted event.
        val received = DeviceIntelligence.interactionEvents.first()
        assertEquals(event, received)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.InteractionEventsPropertyTest"
```

Expected: compilation failure — `interactionEvents` and `installRemoteInteractionAggregatorForTesting` are unresolved.

- [ ] **Step 4: Add `interactionEvents` to `DeviceIntelligence`**

In `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/DeviceIntelligence.kt`, add the following inside the `public object DeviceIntelligence { … }` block (locate a sensible spot, e.g. near other public read-only properties; if none exist, place it just below the `object DeviceIntelligence {` opening line). Add `import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator` and `import kotlinx.coroutines.flow.SharedFlow` at the top:

```kotlin
    /**
     * Process-singleton backing aggregator. Set exactly once by
     * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider]
     * during `onCreate`. Tests may overwrite via
     * [installRemoteInteractionAggregatorForTesting].
     */
    @Volatile
    private var remoteInteractionAggregator: RemoteInteractionAggregator =
        RemoteInteractionAggregator.newProductionInstance()

    /**
     * Hot stream of [InteractionEvent]s emitted by the
     * remote-interaction detector family. See
     * `docs/superpowers/specs/2026-05-19-remote-interaction-detector-design.md`
     * §6.2. Phase 1 ships the flow as a no-op channel (no detector
     * populates it yet); subsequent phases land detectors and
     * listeners that emit through it.
     *
     * @since 1.2.0
     */
    public val interactionEvents: SharedFlow<InteractionEvent>
        get() = remoteInteractionAggregator.events

    /**
     * Replaces the process-singleton aggregator with the given
     * instance. Called by
     * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider]
     * at boot, and from test source sets that need a deterministic
     * aggregator. `internal` visibility keeps it out of the host-app
     * consumer surface — Kotlin's same-module rule means the unit
     * test in `src/test/` can still reach it without exposing it
     * to downstream consumers.
     */
    internal fun installRemoteInteractionAggregator(
        aggregator: RemoteInteractionAggregator,
    ) {
        remoteInteractionAggregator = aggregator
    }
```

If the codebase already has a convention like `@VisibleForTesting` from `androidx.annotation`, prefer that annotation over the suffixed name. If not, the name documents the intent.

- [ ] **Step 5: Wire production aggregator construction in `DeviceIntelligenceInitProvider`**

Open `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/DeviceIntelligenceInitProvider.kt`. Find `onCreate(): Boolean` (or whichever lifecycle method this InitProvider uses for one-time setup). Add at the top of that method body (after any null-context guard):

```kotlin
        // Phase 1 of RemoteInteraction: construct the process-singleton
        // aggregator and install it. The SessionFindingsAggregator default
        // (added in Task 9) would otherwise create a second instance and
        // their snapshots would diverge.
        val interaction = RemoteInteractionAggregator.newProductionInstance()
        DeviceIntelligence.installRemoteInteractionAggregator(interaction)
```

Add the import: `import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator`.

ALSO: if `DeviceIntelligenceInitProvider` constructs `SessionFindingsAggregator` directly, pass the same `interaction` instance to it explicitly to avoid the two singletons diverging:

```kotlin
        // …if you see something like:
        val session = SessionFindingsAggregator( /* existing deps */ )
        // …change it to:
        val session = SessionFindingsAggregator(
            /* existing deps */,
            remoteInteractionAggregator = interaction,
        )
```

- [ ] **Step 6: Run all tests**

```
./gradlew :deviceintelligence:testDebugUnitTest
```

Expected: full unit-test suite passes (including the new `InteractionEventsPropertyTest` and the existing tests).

- [ ] **Step 7: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/DeviceIntelligence.kt \
        deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/DeviceIntelligenceInitProvider.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/InteractionEventsPropertyTest.kt
git commit -m "feat(api): DeviceIntelligence.interactionEvents + boot wiring"
```

---

## Task 11: Extend `TelemetryJson` codec to encode `SessionFindings.remoteInteraction`

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/TelemetryJson.kt`
- Test: `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsCodecTest.kt`

- [ ] **Step 1: Inspect existing `TelemetryJson.kt`**

Read the file. Identify:
1. Which function encodes `SessionFindings` (if `TelemetryJson` encodes `SessionFindings` at all — it may only encode `TelemetryReport`; check before adding).
2. The existing key-sorting / detail-encoding helpers (`kvSortedStringMap`, etc.).
3. Whether there is an existing block-shape pattern for "embedded sub-object" similar to what we need.

If `TelemetryJson` does NOT currently encode `SessionFindings` (only `TelemetryReport`), this task changes shape: the encoder lives on `SessionFindings` directly via an extension, mirroring `TelemetryReport.toIntegritySignals()`. Decide based on what's already there before writing code; the test below assumes the SessionFindings path exists. If it doesn't, adapt to whatever encoding the project actually uses for `SessionFindings`.

- [ ] **Step 2: Write the failing test**

Create `deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsCodecTest.kt`:

```kotlin
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
```

- [ ] **Step 3: Run test to verify it fails**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionFindingsCodecTest"
```

Expected: compilation failure — `encodeRemoteInteraction` unresolved.

- [ ] **Step 4: Add the encoder function**

In `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/TelemetryJson.kt`, add a new function (inside the existing `TelemetryJson` object, alongside other encoders). Use the existing JSON-building helpers — do NOT invent a parallel JSON style. Add `import io.ssemaj.deviceintelligence.RemoteInteractionFindings` and `import io.ssemaj.deviceintelligence.InteractionEventKind`:

```kotlin
    /**
     * Encodes a [RemoteInteractionFindings] snapshot as the
     * `remote_interaction` JSON object embedded in
     * [io.ssemaj.deviceintelligence.SessionFindings] wire output.
     *
     * Key ordering is deterministic (alphabetical) and keys use
     * snake_case to match the existing wire format conventions in
     * this codec. Phase 1: the populated fields are
     * `event_counts` and `highest_severity_observed`; the rest are
     * empty arrays / null / `false` defaults until later phases
     * populate them.
     */
    @JvmStatic
    public fun encodeRemoteInteraction(f: RemoteInteractionFindings): String {
        val sb = StringBuilder()
        sb.append('{')

        sb.append(""""active_device_admins":""")
        appendJsonStringArray(sb, f.activeDeviceAdmins)
        sb.append(',')

        sb.append(""""active_vpn_owner_package":""")
        appendJsonStringOrNull(sb, f.activeVpnOwnerPackage)
        sb.append(',')

        sb.append(""""capability_profile_matches":[],""")
        // Phase 1: array shape only; Phase 4 populates entries.

        sb.append(""""enabled_a11y_services":[],""")
        sb.append(""""event_counts":""")
        appendSortedEventCountsObject(sb, f.eventCounts)
        sb.append(',')

        sb.append(""""external_input_devices":[],""")

        sb.append(""""highest_severity_observed":""")
        appendJsonString(sb, f.highestSeverityObserved.name)
        sb.append(',')

        sb.append(""""notification_listener_packages":""")
        appendJsonStringArray(sb, f.notificationListenerPackages)
        sb.append(',')

        sb.append(""""overlay_capable_packages":""")
        appendJsonStringArray(sb, f.overlayCapablePackages)
        sb.append(',')

        sb.append(""""remote_control_packages":[],""")

        sb.append(""""screen_capture_active":""")
        sb.append(f.screenCaptureActive)
        sb.append(',')

        sb.append(""""screen_capture_active_since":""")
        sb.append(f.screenCaptureActiveSince?.toString() ?: "null")

        sb.append('}')
        return sb.toString()
    }

    private fun appendSortedEventCountsObject(
        sb: StringBuilder,
        counts: Map<InteractionEventKind, Int>,
    ) {
        sb.append('{')
        var first = true
        counts
            .toSortedMap(compareBy { it.name })
            .forEach { (kind, count) ->
                if (!first) sb.append(',')
                first = false
                appendJsonString(sb, kind.name)
                sb.append(':')
                sb.append(count)
            }
        sb.append('}')
    }
```

The three helper functions `appendJsonString`, `appendJsonStringOrNull`, `appendJsonStringArray` are assumed to exist in the existing `TelemetryJson` codec. If they don't (or have different names), substitute the existing project helpers — DO NOT add a parallel JSON-escaping implementation.

- [ ] **Step 5: Run tests to verify pass**

```
./gradlew :deviceintelligence:testDebugUnitTest --tests "io.ssemaj.deviceintelligence.RemoteInteractionFindingsCodecTest"
```

Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/TelemetryJson.kt \
        deviceintelligence/src/test/kotlin/io/ssemaj/deviceintelligence/RemoteInteractionFindingsCodecTest.kt
git commit -m "feat(codec): encode RemoteInteractionFindings to JSON wire format"
```

---

## Task 12: Full-suite regression check + run instrumented-build sanity

**Files:**
- No code changes — full-suite regression run.

- [ ] **Step 1: Run the full JVM unit-test suite**

```
./gradlew :deviceintelligence:testDebugUnitTest
```

Expected: ALL tests pass. If any pre-existing test broke from Phase 1's additions, fix the call site (most likely culprit: a test or production caller that constructed `SessionFindings` positionally without the new `remoteInteraction` parameter; the default value should have covered this, but a positional Java caller might still need touching).

- [ ] **Step 2: Build the sample app modules to confirm no consumer-breaking surface change**

```
./gradlew :samples:assembleDebug
```

Replace `:samples` with the actual sample-module path if the project uses different module names (check `settings.gradle.kts`). Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Run the AGP plugin's own tests**

```
./gradlew :deviceintelligence-gradle:test
```

Expected: PASS. Phase 1 did not touch the gradle plugin, but verifying nothing broke is cheap.

- [ ] **Step 4: Lint**

```
./gradlew :deviceintelligence:lintDebug
```

Expected: no new warnings introduced by Phase 1 files. Fix any new warnings before moving on.

- [ ] **Step 5: Commit any lint-fixup changes if needed**

```bash
git status
# If clean, skip the commit step. If files changed:
git add <changed-files>
git commit -m "chore(interaction): address lint findings from Phase 1"
```

---

## Task 13: Add CHANGELOG entry and version bump

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `gradle.properties`

- [ ] **Step 1: Check current version and CHANGELOG style**

```
grep "VERSION_NAME" /home/joseph/AndroidStudioProjects/DeviceIntelligence/gradle.properties
head -30 /home/joseph/AndroidStudioProjects/DeviceIntelligence/CHANGELOG.md
```

Note the existing version string (likely `1.1.0`) and the heading shape (likely `## [1.1.0] — YYYY-MM-DD`).

- [ ] **Step 2: Bump `VERSION_NAME` in `gradle.properties`**

Open `gradle.properties`. Change `VERSION_NAME=1.1.0` (or whatever current is) to `VERSION_NAME=1.2.0-alpha01`. The `-alpha01` suffix matches the project's existing prerelease convention if any; if the project does not use prerelease suffixes, use `1.2.0-SNAPSHOT` or whatever shape it does use. Inspect `git log --oneline | grep release:` for the answer.

- [ ] **Step 3: Add CHANGELOG entry**

Open `CHANGELOG.md`. At the top, just after the title, add:

```markdown
## [1.2.0-alpha01] — 2026-05-19

### Added — RemoteInteraction detector family (Phase 1: foundations)

Foundational types, aggregator, public API, and `IntegritySignal`
extension for the new RemoteInteraction detector family. See
`docs/superpowers/specs/2026-05-19-remote-interaction-detector-design.md`
for the complete design and `docs/superpowers/plans/2026-05-19-remote-interaction-phase-1.md`
for the Phase 1 implementation plan.

- `DeviceIntelligence.interactionEvents: SharedFlow<InteractionEvent>` —
  hot stream of remote-interaction events. Phase 1 is a no-op channel;
  Phase 2 detectors land in 1.3.0.
- `SessionFindings.remoteInteraction: RemoteInteractionFindings` —
  snapshot field defaulting to `RemoteInteractionFindings.EMPTY`.
- `IntegritySignal.REMOTE_INTERACTION_HIGH_RISK` /
  `REMOTE_INTERACTION_AMBIENT_RISK` / `REMOTE_INTERACTION_CONTEXT` —
  three new high-level signals; mapper routes `remote_interaction.*`
  finding kinds by severity tier.
- `InteractionEvent` sealed hierarchy with 13 variants covering every
  signal the design will surface in subsequent phases.
- New `remote_interaction` block in the TelemetryJson wire output.

### Unchanged

- `IntegrityVerdict` (Play-Integrity-shaped `DeviceTier` ×
  `AppRecognition`) is intentionally untouched — remote-interaction
  signals are orthogonal and surface via `IntegritySignal` only.
```

- [ ] **Step 4: Verify build with the new version**

```
./gradlew :deviceintelligence:assembleDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md gradle.properties
git commit -m "release: 1.2.0-alpha01 (RemoteInteraction Phase 1 foundations)"
```

---

## Definition of done for Phase 1

All of the following must be true before declaring Phase 1 complete:

- [ ] `./gradlew :deviceintelligence:testDebugUnitTest` passes with the 7 new test classes added by this plan.
- [ ] `./gradlew :deviceintelligence:assembleDebug` and `:deviceintelligence:lintDebug` pass.
- [ ] `./gradlew :samples:assembleDebug` (or equivalent sample-module path) builds without modification — Phase 1 is fully source-compatible.
- [ ] `git log` shows 13 small, focused commits — one per task.
- [ ] `CHANGELOG.md` and `gradle.properties` reflect `1.2.0-alpha01`.
- [ ] A consumer can call `DeviceIntelligence.interactionEvents.collect { … }` and the collector returns immediately (no events arrive because no detector emits — that is correct for Phase 1).
- [ ] A consumer reading `SessionFindings.remoteInteraction` from a regular `DeviceIntelligence.collect(context)` call sees `RemoteInteractionFindings.EMPTY` populated with `highestSeverityObserved = INFO` and `eventCounts = emptyMap()`.

---

## Handoff to Phase 2

Phase 2 (1.3.0) adds the snapshot detectors that begin emitting events into the aggregator built in Phase 1:

- `A11yAbuseDetector` (§5.1 of spec)
- `RemoteControlAppDetector` — package-signature strategy only (§5.2 of spec)
- `InputSourceDetector` (§5.3 of spec)
- `OverlayDetector` (§5.4 of spec)
- `InteractionContextDetector` (§5.5 of spec)
- `InteractionAllowlistReader` + bundled `interaction_allowlist.v1.json`
- Robolectric tests for each detector
- Extends `PrewarmCoordinator` to call `RemoteInteractionAggregator.runSnapshot(ctx)`

That work gets its own brainstorm + spec + plan cycle, scaffolded against this Phase 1 foundation. No Phase 1 code needs to change for Phase 2 to land.
