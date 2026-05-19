# RemoteInteraction Detector Family — Design

**Date:** 2026-05-19
**Status:** Draft — awaiting author review
**Author:** joseph (iamjosephmj)
**Target release:** DeviceIntelligence 1.2.0 (minor)
**Related:** `docs/DETECTORS.md`, `NATIVE_INTEGRITY_DESIGN.md`, `CTF_ROADMAP.md`

---

## 1. Summary

Add a new detector family — `RemoteInteraction` — to DeviceIntelligence that surfaces RAT / remote-control tooling, accessibility-service abuse, external-input-device anomalies, screen-capture activity, and overlay/tapjacking conditions. The family combines three runtime data sources (snapshot scans, system listeners, and compile-time-injected event hooks) into a single aggregator that exposes both a live `SharedFlow<InteractionEvent>` and a roll-up snapshot on `SessionFindings`. Three new high-level `IntegritySignal` values (`REMOTE_INTERACTION_HIGH_RISK`, `REMOTE_INTERACTION_AMBIENT_RISK`, `REMOTE_INTERACTION_CONTEXT`) are introduced; the Play-Integrity-shaped `IntegrityVerdict` is intentionally **not** modified.

Compile-time class instrumentation is added to the existing `:deviceintelligence-gradle` plugin via AGP's `AsmClassVisitorFactory` API, wrapping `Activity.dispatchTouchEvent` / `dispatchKeyEvent` / `onWindowFocusChanged` and rewriting `MediaProjectionManager.createScreenCaptureIntent` and overlay `WindowManager.addView` call sites — universal scope, with explicit opt-out and exclude-prefix escape hatches.

---

## 2. Goals & non-goals

### Goals

- Detect known and unknown remote-control / RAT apps, including capability-based detection that works without an up-to-date package allowlist.
- Detect accessibility-service abuse (the dominant Android RAT vector in 2025: Cerberus, Hydra, BRATA, Hook, GodFather, TeaBot, FluBot families).
- Detect screen-capture activity (own and third-party) including the API 34+ `WindowManager.registerScreenCaptureCallback` signal.
- Detect input arriving from virtual `InputDevice`s, scripted-input tooling, and ADB keyboard injection — both at session-start enumeration and per-event.
- Detect overlay / tapjacking conditions on sensitive screens via `MotionEvent.FLAG_WINDOW_IS_OBSCURED` and an enumeration of `SYSTEM_ALERT_WINDOW` holders.
- Surface signals as a live `SharedFlow` (for in-flow gating, e.g. abort a payment mid-flow) AND as an aggregated `SessionFindings` snapshot (for the existing report consumers).
- Avoid false positives for: legitimate accessibility users (TalkBack, Switch Access), password managers (Bitwarden, 1Password), enterprise MDM, IT-support tools (TeamViewer, AnyDesk on managed devices), and Chromebook/tablet form factors.

### Non-goals

- Detecting what a remote operator is **doing** on the device (out of scope — requires kernel-level visibility).
- Reading another app's memory or intercepting another app's touch events directly (not possible from a normal app).
- Blocking remote-control apps from running (we surface signals; the host app decides policy).
- Adding new Play Integrity-style tiers; `IntegrityVerdict` shape is unchanged.
- Foreground service / persistent background work (snapshot + listeners + per-event only).
- Network-level analysis of which apps are calling out to which C2 — orthogonal feature for a later release.

---

## 3. Background

DeviceIntelligence 1.1 covers root, ART/native integrity, cloners, emulators, DEX injection, key attestation, bootloader integrity, and APK tampering. It does **not** cover "what's interacting with the device right now" — accessibility-service abuse, screen-capture by another app, remote-control tooling, and scripted-input injection are unaddressed.

The 2025 mobile-malware landscape (Hook, GodFather, BRATA, TeaBot, FluBot, Cerberus) is dominated by accessibility-service-driven banking trojans. Legitimate remote-support tools (TeamViewer QuickSupport, AnyDesk) are also a recurring fraud vector ("tech support" scams). Per-screen detection of these conditions is a frequent gap in commercial RASP products.

This work also unblocks a new CTF flag (Flag 6 — Remote Interaction & A11y Abuse) per the project's roadmap.

---

## 4. Architecture

### 4.1 Module layout

No new modules. All runtime code lives in `:deviceintelligence` under a new package `io.ssemaj.deviceintelligence.internal.interaction.*`. Compile-time code lives in `:deviceintelligence-gradle` under a new package `io.ssemaj.deviceintelligence.gradle.instrumentation.*` (sibling of the existing `tasks/` and `internal/` packages).

### 4.2 Runtime topology

```
┌─────────────────────────────────────────────────────────────────┐
│ DeviceIntelligence (public)                                     │
│   .interactionEvents: SharedFlow<InteractionEvent>   ← new      │
│   SessionFindings.remoteInteraction: …Findings       ← new      │
└─────────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────┴───────────────────────────────────┐
│ RemoteInteractionAggregator                                     │
│  - rolling counts + last-seen per signal kind                   │
│  - MutableSharedFlow<InteractionEvent> (replay 16, buf 64)      │
│  - RemoteInteractionFindings snapshot for SessionFindings       │
└─────────────────────────────────────────────────────────────────┘
       ▲                    ▲                        ▲
┌──────┴─────────┐  ┌───────┴────────────┐  ┌────────┴──────────┐
│ Snapshot       │  │ Lifecycle listeners│  │ Bytecode-injected │
│ detectors      │  │ (sidecar)          │  │ hooks             │
│ (one-shot)     │  │ A11yStateListener  │  │ Activity dispatch │
│ A11yEnum       │  │ InputDeviceListener│  │ Overlay add-view  │
│ KnownPackages  │  │ ScreenCaptureCb    │  │ MediaProj call    │
│ CapabilityProf │  │ ConnectivityVPN    │  │ sites             │
│ OverlayGrants  │  │ NotifListenerEnum  │  │                   │
│ InputDevsEnum  │  │                    │  │                   │
└────────────────┘  └────────────────────┘  └───────────────────┘
```

### 4.3 Boot path

Two sibling `ContentProvider`s (independent failure domains, matching the existing `DeviceIntelligenceInitProvider` pattern):

- `DeviceIntelligenceInitProvider` (existing) — instantiates the component graph including `RemoteInteractionAggregator`. The existing `PrewarmCoordinator` is extended to also call `RemoteInteractionAggregator.runSnapshot(appCtx)` on `Dispatchers.IO`.
- `RemoteInteractionInitProvider` (new) — calls `aggregator.attachListeners(appCtx)` from its `onCreate`, deferred via `LibraryScope.launch` so it never blocks process startup.

If the listener provider fails to start (rare OEM permission edge cases), snapshot detection and the bytecode-injected hot path continue to work.

### 4.4 Compile-time topology

Two AGP `AsmClassVisitorFactory`s registered on `androidComponents.onVariants { variant -> variant.instrumentation.transformClassesWith(...) }`:

- `ActivityDispatchVisitorFactory` — `InstrumentationScope.ALL`, wraps Activity input dispatch.
- `FrameworkCallSiteVisitorFactory` — `InstrumentationScope.ALL`, rewrites specific framework call sites in user code.

A new `RemoteInteractionInitProvider` `<provider>` entry is merged into the host manifest by the existing `GenerateOptionalManifestTask`.

---

## 5. Detector catalog

22 distinct **detection signals** across 5 sub-families. (A signal is one rule that fires; it surfaces through one of ~12 `InteractionEvent` variants — multiple signals can share an event variant with different field values, e.g. several A11y-abuse signals all produce `A11yServiceEnabled` events distinguished by `capabilities` / `installerPackage` / `firstInstallMs`.) Severity tiers — `HIGH`, `MEDIUM`, `INFO` — drive the high-level `IntegritySignal` bucketing.

### 5.1 Accessibility-service abuse (`A11yAbuseDetector`)

| Signal | API | Sev | FP notes |
|---|---|---|---|
| Enumerate enabled A11y services | `AccessibilityManager.getEnabledAccessibilityServiceList(FEEDBACK_ALL_MASK)` | INFO baseline | TalkBack, Switch Access, Voice Access are allowlisted |
| Service from unknown installer | `PackageManager.getInstallSourceInfo(pkg).installingPackageName` | MED | Sideloaded legit tool |
| Service with `canRetrieveWindowContent` + `canPerformGestures` + `flagRequestFilterKeyEvents` | `AccessibilityServiceInfo.capabilities` | HIGH | Password managers allowlisted (Bitwarden, 1Password, etc.) |
| Service installed in last 24h | `PackageInfo.firstInstallTime` vs session start | MED | Just-installed legitimate tool |
| A11y service in package that also holds `SYSTEM_ALERT_WINDOW` | Cross-check | HIGH | Strong RAT pattern |
| **Live**: A11y enabled state changes during session | `AccessibilityManager.AccessibilityStateChangeListener` | HIGH | User-toggled mid-flow is suspicious |

### 5.2 Remote-control app detection (`RemoteControlAppDetector`)

Two strategies run in parallel:

**Package signature strategy** — known packages and signing certs shipped as a bundled asset:

| Signal | API | Sev |
|---|---|---|
| Known RAT / remote-control package present | `PackageManager.getInstalledPackages()` + `assets/io.ssemaj.deviceintelligence/remote_packages.json` | MED–HIGH per entry |
| Package signed by known-malicious cert | `PackageInfo.signingInfo.apkContentsSigners` SHA-256 vs bundled list | HIGH |
| **Live**: another package's screen capture starts | `WindowManager.registerScreenCaptureCallback` (API 34+) | HIGH |

**Capability-profile strategy** — name-agnostic, scores apps by declared capabilities:

| Signal | Score contribution |
|---|---|
| Declares `<service android:foregroundServiceType="mediaProjection">` | +1 |
| Declares `AccessibilityService` with `canPerformGestures` | +1 |
| Holds `SYSTEM_ALERT_WINDOW` | +1 |
| Holds `BIND_ACCESSIBILITY_SERVICE` (declaration) | +1 |
| Holds `FOREGROUND_SERVICE_MEDIA_PROJECTION` (API 34+) | +1 |
| Holds `RECORD_AUDIO` + `INTERNET` + persistent foreground service | +1 |

Score ≥3 → MEDIUM event `RemoteControlAppDetected(matchStrategy=CAPABILITY_PROFILE)`; ≥5 → HIGH. Behavioral modifiers (§7.4) can shift up or down.

### 5.3 Input-source integrity (`InputSourceDetector`)

| Signal | API | Sev |
|---|---|---|
| External HID keyboard connected | `InputManager.getInputDeviceIds()` + `SOURCE_KEYBOARD` non-virtual | INFO–MED |
| Virtual input device present | `InputDevice.isVirtual` | HIGH |
| **Per-event (compile-time hook)**: touch with `getSource() & SOURCE_TOUCHSCREEN == 0` | `MotionEvent.getSource()` / `getDevice()` | HIGH |
| **Per-event**: key event from virtual device | `KeyEvent.getDevice().isVirtual` | HIGH |
| **Live**: InputDevice added/removed during session | `InputManager.InputDeviceListener` | MED |

Chromebook / `UI_MODE_TYPE_DESK` form factors downgrade external-input findings two tiers (§7.4).

### 5.4 Overlay & tapjacking (`OverlayDetector`)

| Signal | API | Sev |
|---|---|---|
| Apps holding `SYSTEM_ALERT_WINDOW` permission | `PackageManager.getPackagesHoldingPermissions(...)` | INFO baseline |
| Foreground window obscured during input dispatch | `MotionEvent.FLAG_WINDOW_IS_OBSCURED` / `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (via injected dispatch wrapper, fires on any Activity) | HIGH |
| Host code adds overlay window | bytecode call-site hook on `WindowManager.addView` | INFO |

### 5.5 Adjacent / cheap-win signals (`InteractionContextDetector`)

| Signal | API | Sev |
|---|---|---|
| Active VPN | `ConnectivityManager` NET_CAPABILITY_VPN + getActiveNetwork() ownership | INFO |
| Enabled NotificationListener services | `NotificationManager.isNotificationListenerAccessGranted` per pkg | MED |
| Active DeviceAdmin / DeviceOwner | `DevicePolicyManager.getActiveAdmins()` | INFO–HIGH |
| `ADB_ENABLED` + `ADB_WIFI_ENABLED` | `Settings.Global` | MED |
| `INSTALL_NON_MARKET_APPS` granted to non-Play installer | `PackageManager.canRequestPackageInstalls()` per source | MED |

### 5.6 Signal-to-finding mapping

Each `InteractionEvent` becomes a stable-kinded `Finding` in `TelemetryReport.findings`. Kinds use the prefix `remote_interaction.` followed by a stable suffix (e.g. `remote_interaction.a11y_high_capability_service`, `remote_interaction.remote_control_app_capability_match`, `remote_interaction.suspicious_input_dispatch`, `remote_interaction.screen_capture_active`).

---

## 6. Public API surface

All additions are source- and binary-compatible with the existing v1.1 surface.

### 6.1 Event hierarchy

```kotlin
package io.ssemaj.deviceintelligence

public sealed interface InteractionEvent {
    public val severity: InteractionSeverity
    public val timestampMs: Long
    public val source: InteractionSource

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

    public data class A11yStateChanged(val enabled: Boolean, /*...*/) : InteractionEvent
    public data class RemoteControlAppDetected(
        val packageName: String,
        val matchStrategy: MatchStrategy,
        val capabilityScore: Int,
        val isSideloaded: Boolean,
        /*...*/
    ) : InteractionEvent
    public data class ScreenCaptureStarted(val initiatedByHost: Boolean, /*...*/) : InteractionEvent
    public data class InputDeviceAttached(val deviceId: Int, val name: String, val isVirtual: Boolean, val sources: Int, /*...*/) : InteractionEvent
    public data class SuspiciousInputDispatch(val activityClass: String, val sourceFlags: Int, val deviceIsVirtual: Boolean, /*...*/) : InteractionEvent
    public data class WindowObscured(val activityClass: String, val partial: Boolean, /*...*/) : InteractionEvent
    public data class OverlayWindowAddedByHost(val viewClass: String, /*...*/) : InteractionEvent
    public data class VpnActivated(val ownerPackage: String?, /*...*/) : InteractionEvent
    public data class NotificationListenerEnabled(val packageName: String, /*...*/) : InteractionEvent
    public data class DeviceAdminActive(val packageName: String, val isDeviceOwner: Boolean, /*...*/) : InteractionEvent
    public data class DetectorFailed(val detectorName: String, val reasonClass: String, /*...*/) : InteractionEvent
    public data class RuntimeMismatch(val pluginVersion: String, val runtimeVersion: String, /*...*/) : InteractionEvent
}

public enum class InteractionSeverity { INFO, MEDIUM, HIGH }
public enum class InteractionSource { SNAPSHOT, LISTENER, INSTRUMENTED }
public enum class A11yCapability { RETRIEVE_WINDOW_CONTENT, PERFORM_GESTURES, FILTER_KEY_EVENTS, TOUCH_EXPLORATION, /*...*/ }
public enum class MatchStrategy { PACKAGE_NAME_ALLOWLIST, SIGNING_CERT_ALLOWLIST, CAPABILITY_PROFILE, BEHAVIORAL_COMPOSITE }
```

### 6.2 Extension to `DeviceIntelligence`

```kotlin
public interface DeviceIntelligence {
    // …existing API…

    /**
     * Hot SharedFlow of remote-interaction events emitted during the active
     * session. Replays the last 16 events for late collectors. Backed by
     * extraBufferCapacity = 64 with onBufferOverflow = DROP_OLDEST so a slow
     * consumer cannot stall detection.
     */
    public val interactionEvents: SharedFlow<InteractionEvent>
}
```

### 6.3 Extension to `SessionFindings`

```kotlin
public data class SessionFindings(
    // …existing fields…
    val remoteInteraction: RemoteInteractionFindings,
)

public data class RemoteInteractionFindings(
    val enabledA11yServices: List<A11yServiceSummary>,
    val remoteControlPackages: List<RemoteControlPackageSummary>,
    val capabilityProfileMatches: List<CapabilityProfileMatch>,
    val externalInputDevices: List<InputDeviceSummary>,
    val overlayCapablePackages: List<String>,
    val notificationListenerPackages: List<String>,
    val activeDeviceAdmins: List<String>,
    val activeVpnOwnerPackage: String?,
    val screenCaptureActive: Boolean,
    val screenCaptureActiveSince: Long?,
    val eventCounts: Map<InteractionEventKind, Int>,
    val highestSeverityObserved: InteractionSeverity,
)
```

### 6.4 New `IntegritySignal` enum values

Three additions to the existing `IntegritySignal` enum (consumer pivot surface):

- `REMOTE_INTERACTION_HIGH_RISK` — at least one HIGH-severity finding. Advisory; weight similarly to `HOOKING_FRAMEWORK_DETECTED`.
- `REMOTE_INTERACTION_AMBIENT_RISK` — at least one MEDIUM-severity finding (known remote-support tools, notification listeners, recently-installed A11y services). One factor among several; not a blocker on its own.
- `REMOTE_INTERACTION_CONTEXT` — INFO only (TalkBack on, external keyboard, VPN, MDM). Never a compromise indicator; useful for explaining other signals.

The new values are added at the end of `IntegritySignal` to preserve ordinal stability for any reflective consumer.

### 6.5 Relationship to `IntegrityVerdict`

`IntegrityVerdict` (Play-Integrity-shaped `DeviceTier` × `AppRecognition`) is **not modified**. Remote-interaction signals are orthogonal to that contract; folding them in would muddy the wire-format compatibility with Google Play Integrity that consumers currently rely on.

### 6.6 Gradle DSL extension

```kotlin
deviceIntelligence {
    // …existing…
    interaction {
        instrumentActivities = true                    // default true
        instrumentFrameworkCallSites = true            // default true
        capabilityScan = CapabilityScanMode.LAUNCHER_ONLY  // FULL requires QUERY_ALL_PACKAGES
        extraAllowedPackages = listOf(
            AllowedPackage("com.acme.it.support", signerSha256 = "..."),
        )
        extraAllowedA11yServices = listOf(/*...*/)
        demotedRemoteSupport = listOf(/*...*/)
        excludeClassPrefixes = listOf("com.acme.tests.", "com.acme.samples.")
    }
}
```

---

## 7. Bytecode instrumentation strategy

### 7.1 Registration

```kotlin
androidComponents.onVariants { variant ->
    variant.instrumentation.transformClassesWith(
        ActivityDispatchVisitorFactory::class.java,
        InstrumentationScope.ALL
    ) { params -> params.runtimeVersion.set(PluginCoordinates.VERSION) }

    variant.instrumentation.transformClassesWith(
        FrameworkCallSiteVisitorFactory::class.java,
        InstrumentationScope.ALL
    ) { params -> params.runtimeVersion.set(PluginCoordinates.VERSION) }

    variant.instrumentation.setAsmFramesComputationMode(
        FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS
    )
}
```

`InstrumentationScope.ALL` is intentional — library Activities (third-party SDK Activities embedded in the host app) are part of the input-event attack surface and missing them would be a gap. `excludeClassPrefixes` is the documented escape hatch for libraries that conflict.

### 7.2 `ActivityDispatchVisitorFactory`

`isInstrumentable` returns `true` iff `classData.superClasses` contains `android.app.Activity` (transitively covers `AppCompatActivity`, `FragmentActivity`, `ComponentActivity`) and the FQN doesn't match an exclude prefix.

Per matched class, three methods are wrapped:

| Method | Strategy |
|---|---|
| `dispatchTouchEvent(MotionEvent): boolean` | If override exists: prepend `RemoteInteractionRuntime.onTouchEvent(this, ev)` to method body. If not: inject the override that calls runtime + delegates to `super`. |
| `dispatchKeyEvent(KeyEvent): boolean` | Same. |
| `onWindowFocusChanged(boolean): void` | Same — also triggers re-registration of `WindowManager.registerScreenCaptureCallback` for the current window. |

Edge cases:
- **Abstract classes**: the override is injected normally; concrete subclasses inherit it and chain `super` correctly.
- **`final` methods**: when an existing override is `final` in a superclass, we wrap that existing method body in place rather than trying to inject an override in subclasses (which would be a compile error).
- **`final` classes**: the class can't be subclassed, but we're modifying *that* class — injection/wrap proceeds normally.
- **Generated R8 / Hilt / Compose-runtime Activity subclasses**: filtered out via the default `excludeClassPrefixes` (`hilt_aggregated_deps.`, `androidx.hilt.`, etc.) to avoid double-instrumentation collisions and class-load-order issues.

The injected call is wrapped in `try { … } catch (Throwable t) { /* swallow */ }` at the bytecode level so a runtime bug in the SDK can never break the host app's input dispatch.

### 7.3 `FrameworkCallSiteVisitorFactory`

`isInstrumentable` returns `true` for any class **except** those under `android.*`, `androidx.*`, `kotlin.*`, `kotlinx.*`, `io.ssemaj.deviceintelligence.*`, and configured excludes — protects build-perf budget by skipping clearly-uninteresting classes and prevents recursive instrumentation of the SDK itself.

Per class, walks every method body and rewrites these call sites:

| Call site | Rewrite |
|---|---|
| `MediaProjectionManager.createScreenCaptureIntent()` | `RemoteInteractionRuntime.wrapCreateScreenCaptureIntent(receiver)` — calls original, tags as host-initiated, returns unchanged. |
| `MediaProjectionManager.getMediaProjection(int, Intent)` | Same wrap pattern. |
| `WindowManager.addView(View, ViewGroup.LayoutParams)` | Prepended call to `RemoteInteractionRuntime.onHostOverlayAdded(view, params)`; runtime checks if params is overlay-typed before tagging. |

Rewrites preserve operand-stack semantics via `DUP` insertion before the wrapper call. No method signatures change.

### 7.4 Runtime contract & version coupling

The runtime version is injected via the plugin's existing `BuildConfig` mechanism. `RemoteInteractionRuntime.assertCompatibleVersion()` is called at first instrumented hook invocation; mismatch emits `InteractionEvent.RuntimeMismatch` and disables instrumented paths, leaving snapshot + listener paths fully functional.

Static entry points called from instrumented code have stable signatures across minor versions:

```kotlin
@Keep public object RemoteInteractionRuntime {
    @JvmStatic public fun onTouchEvent(activity: Activity, ev: MotionEvent)
    @JvmStatic public fun onKeyEvent(activity: Activity, ev: KeyEvent)
    @JvmStatic public fun onWindowFocusChanged(activity: Activity, hasFocus: Boolean)
    @JvmStatic public fun wrapCreateScreenCaptureIntent(mgr: MediaProjectionManager): Intent
    @JvmStatic public fun wrapGetMediaProjection(mgr: MediaProjectionManager, resultCode: Int, data: Intent): MediaProjection
    @JvmStatic public fun onHostOverlayAdded(view: View, params: ViewGroup.LayoutParams)
    @JvmStatic public fun assertCompatibleVersion()
}
```

Signature changes are SDK major-version bumps and documented in `CHANGELOG.md`.

### 7.5 Sidecar registration (not bytecode)

Listener registration uses the existing `GenerateOptionalManifestTask` to merge a new `<provider android:name=".internal.interaction.RemoteInteractionInitProvider" android:authorities="${applicationId}.di-interaction-init" android:exported="false" android:initOrder="99" tools:node="merge" />` entry. Auto-discovery via ContentProvider mirrors how `DeviceIntelligenceInitProvider` already boots.

### 7.6 Opt-out escape hatches

- `instrumentActivities = false` — skip `ActivityDispatchVisitorFactory` registration.
- `instrumentFrameworkCallSites = false` — skip `FrameworkCallSiteVisitorFactory` registration.
- `excludeClassPrefixes = listOf(...)` — skip specific packages from both visitors (test code, sample code, third-party-lib collisions).
- `capabilityScan = CapabilityScanMode.DISABLED` — skip the entire `RemoteControlAppDetector.CapabilityProfileStrategy` pass.

---

## 8. Data flow

### 8.1 Three input paths converge on `RemoteInteractionAggregator`

**Snapshot (cold, one-shot per process):**
```
PrewarmCoordinator
  → RemoteInteractionAggregator.runSnapshot(ctx) [LibraryScope + Dispatchers.IO]
    → A11yAbuseDetector.scan(ctx)
    → RemoteControlAppDetector.scan(ctx)   // package + capability strategies in parallel via async
    → InputSourceDetector.scan(ctx)
    → OverlayDetector.scan(ctx)
    → InteractionContextDetector.scan(ctx)
    → each emits 0..N InteractionEvent into aggregator.emit(...)
```

**System listeners (warm, session-lifetime):**
```
RemoteInteractionInitProvider.onCreate
  → aggregator.attachListeners(ctx)
    → AccessibilityManager.addAccessibilityStateChangeListener(...)
    → AccessibilityManager.addTouchExplorationStateChangeListener(...)
    → InputManager.registerInputDeviceListener(...)
    → ConnectivityManager.registerNetworkCallback(VPN filter, ...)
    → WindowManager.registerScreenCaptureCallback(...)   // lazy, first instrumented Activity onResume
    → each callback → aggregator.emit(...) on LibraryScope
```

**Bytecode-injected hot path (per input event):**
```
[Instrumented Activity].dispatchTouchEvent(ev)
  → RemoteInteractionRuntime.onTouchEvent(this, ev)   [UI thread, < 50 ns clean path]
    → if suspicious: aggregator.emitFromUiThread(...) [trampolines to LibraryScope]
  → super.dispatchTouchEvent(ev)
```

### 8.2 Aggregator internals

```kotlin
internal class RemoteInteractionAggregator(
    private val scope: CoroutineScope = LibraryScope,
    private val replayCount: Int = 16,
    private val bufferCapacity: Int = 64,
) {
    private val _events = MutableSharedFlow<InteractionEvent>(
        replay = replayCount,
        extraBufferCapacity = bufferCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<InteractionEvent> = _events.asSharedFlow()

    private val counts = ConcurrentHashMap<InteractionEventKind, AtomicInteger>()
    private val lastSeen = ConcurrentHashMap<InteractionEventKind, Long>()
    private val highestSeverity = AtomicReference(InteractionSeverity.INFO)

    internal fun emit(event: InteractionEvent) {
        counts.computeIfAbsent(event.kind) { AtomicInteger(0) }.incrementAndGet()
        lastSeen[event.kind] = event.timestampMs
        bumpSeverity(event.severity)
        _events.tryEmit(event)   // non-suspending; DROP_OLDEST means it always returns true
    }

    internal fun snapshot(): RemoteInteractionFindings = /* fold state */
}
```

### 8.3 Output paths

- **Live**: `DeviceIntelligence.interactionEvents` directly forwards `aggregator.events`. Consumers collect on their own scopes (typically `lifecycleScope` or a screen-level ViewModel scope).
- **Snapshot**: `SessionFindingsAggregator` (existing) gains a step that pulls `aggregator.snapshot()` and packs it into `SessionFindings.remoteInteraction`. No change to existing rollup trigger semantics.

### 8.4 Session boundaries

Per existing SDK semantics, "session" == process lifetime — `LibraryScope` and `SessionFindingsAggregator` are process-singletons. `RemoteInteractionAggregator` follows the same model: counts cumulative since process start; `SharedFlow.replay` allows late collectors to catch up on recent history.

Per-screen reset (e.g., a payment flow wanting a clean slate per attempt) is a host-composition concern: `interactionEvents.dropWhile { it.timestampMs < screenStart }`. No SDK API for this.

### 8.5 Backpressure

`DROP_OLDEST` + 64-slot buffer + 16-slot replay: a stalled consumer loses oldest unread events; emitters never block. This is non-negotiable because the bytecode-injected hot path emits from the UI thread.

---

## 9. Verdict semantics & allowlists

### 9.1 Three-layer allowlisting

**Layer 1 — bundled platform allowlist (asset shipped with SDK)**

`assets/io.ssemaj.deviceintelligence/interaction_allowlist.v1.json`:

```json
{
  "schema_version": 1,
  "a11y_services_system": [
    { "pkg": "com.google.android.marvin.talkback", "signers": ["sha256:..."] },
    { "pkg": "com.google.android.apps.accessibility.voiceaccess", "signers": ["sha256:..."] },
    { "pkg": "com.google.android.apps.accessibility.auditor", "signers": ["sha256:..."] },
    { "pkg": "com.android.switchaccess", "signers": ["sha256:..."] }
  ],
  "a11y_services_password_managers": [
    { "pkg": "com.x8bit.bitwarden", "signers": ["sha256:..."] },
    { "pkg": "com.agilebits.onepassword", "signers": ["sha256:..."] },
    { "pkg": "com.lastpass.lpandroid", "signers": ["sha256:..."] },
    { "pkg": "com.dashlane.frozenapps", "signers": ["sha256:..."] },
    { "pkg": "com.keepassdroid", "signers": ["sha256:..."] }
  ],
  "remote_support_demoted": [
    { "pkg": "com.teamviewer.quicksupport.market", "signers": ["sha256:..."] },
    { "pkg": "com.anydesk.anydeskandroid", "signers": ["sha256:..."] },
    { "pkg": "com.splashtop.streamer", "signers": ["sha256:..."] }
  ]
}
```

Allowlist entries are matched on **both** package name AND signing certificate. Repackaged apps with the same package name but different signers do not get allowlist treatment.

**Layer 2 — host app overrides (baked at compile time)**

Host adds entries via `deviceIntelligence { interaction { extraAllowedPackages = listOf(...) } }`. These are merged into the on-device asset by extending `BakeFingerprintTask`. Signer pinning is required; an entry without `signerSha256` is a build-time error.

**Layer 3 — behavioral confidence modifiers**

Severity calculator applies these modifiers before assigning final tier:

| Modifier | Adjustment |
|---|---|
| Installer is `com.android.vending` / `com.google.android.feedback` | -1 tier |
| Signed with debug cert | +1 tier |
| `firstInstallTime == lastUpdateTime` AND installed in the last 24h | +1 tier |
| Target SDK < 26 | +1 tier |
| Capability-profile match (≥3 capabilities) | +1 tier |
| Capability-profile match (≥5 capabilities) | +2 tiers |
| Device is `UI_MODE_TYPE_DESK` / `PackageManager.FEATURE_PC` AND finding is external-input | -2 tiers |

Modifiers compose additively; result clamped to `[INFO, HIGH]`.

### 9.2 Schema versioning

`interaction_allowlist.v1.json` carries `schema_version`. `InteractionAllowlistReader` mirrors `FingerprintAssetReader`'s handling: unknown future schemas fall back gracefully (emit `remote_interaction.allowlist_schema_mismatch` finding, treat all matches as un-allowlisted = fail-closed).

---

## 10. Performance, errors, ProGuard

### 10.1 Performance budgets (asserted in CI)

| Path | Budget |
|---|---|
| Per-touch-event UI thread (clean) | < 50 ns; zero allocation |
| Per-touch-event UI thread (suspicious) | < 5 µs; one event allocation |
| Snapshot detector total (cold) | < 200 ms wall-clock on Pixel 6 |
| Listener registration aggregate | < 5 ms |
| ASM transform build-time delta | < 1 s for 200-class app |
| Aggregator steady-state heap | < 64 KB |

### 10.2 Failure-mode posture

- Any single detector throwing is caught (`runCatching`), surfaced as `DetectorFailed` event at INFO, doesn't kill peers.
- Listener registration failures logged once, that signal path disabled, others independent.
- `RemoteInteractionRuntime.onTouchEvent` throwing is impossible (bytecode-injected `try/catch` swallows; failure counted into a per-process tally exposed as a finding).
- ASM visitor throwing fails the Gradle build with the offending class FQN.
- Plugin/runtime version mismatch is graceful: log error, emit `RuntimeMismatch` event, disable instrumented paths; snapshot + listener paths continue.
- Allowlist asset missing/corrupt: fail-closed (treat matches as un-allowlisted), emit `allowlist_unavailable` finding at CRITICAL.
- `QUERY_ALL_PACKAGES` requested via `capabilityScan = FULL` but not declarable: build-time error.

### 10.3 Consumer ProGuard rules

```
-keep,allowoptimization class io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionRuntime {
    public static *** onTouchEvent(...);
    public static *** onKeyEvent(...);
    public static *** onWindowFocusChanged(...);
    public static *** wrapCreateScreenCaptureIntent(...);
    public static *** wrapGetMediaProjection(...);
    public static *** onHostOverlayAdded(...);
    public static *** assertCompatibleVersion();
}
-keep class io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionInitProvider
-keepclassmembers class io.ssemaj.deviceintelligence.InteractionEvent$* { *; }
-keep class io.ssemaj.deviceintelligence.internal.interaction.AllowlistEntry { *; }
-keep class io.ssemaj.deviceintelligence.internal.interaction.AllowlistDocument { *; }
```

### 10.4 Manifest posture

- `RemoteInteractionInitProvider` merged via `tools:node="merge"`, dummy authority, non-exported.
- `QUERY_ALL_PACKAGES` **never** in the SDK manifest; only added by `GenerateOptionalManifestTask` when host opts in via `capabilityScan = FULL`.
- No `<queries>` block in SDK manifest (tipping off researchers/users via `dumpsys package queries`).

### 10.5 Logging discipline

- INFO/MEDIUM events: no logs by default (findings only).
- HIGH events: one `Log.w` with stable text, no dynamic strings (grep-able from `bugreport`).
- Plugin/runtime errors: `Log.e` with class names so users can see what to exclude.
- Verbose-mode timing logs gated by a debug-only `BuildConfig.VERBOSE_INTERACTION` flag.

### 10.6 Compatibility matrix

| Surface | Requirement |
|---|---|
| Runtime min SDK | 24 (matches existing `:deviceintelligence`); per-signal gating for higher-API features |
| AGP | 8.0+ for `AsmClassVisitorFactory`; validated against 8.7 and 9.0-rc |
| `registerScreenCaptureCallback` | API 34+ only; signal absent on older devices |
| `InputDeviceListener` | API 16+ |
| A11y state listener | API 17+ |
| Kotlin | matches existing; `@JvmStatic` on public entry points |
| R8 | full mode supported with the consumer rules above |

---

## 11. Testing strategy

### 11.1 JVM unit tests (`:deviceintelligence/src/test/`)

- `RemoteInteractionAggregatorTest` — emit ordering, severity escalation, snapshot folding, DROP_OLDEST flood test, N-thread concurrent emit producing deterministic counts.
- `CapabilityProfileScorerTest` — 50+ table-driven cases over the capability triple combinations × behavioral modifiers.
- `InteractionAllowlistReaderTest` — schema-version handling, signer pinning, malformed JSON, future-schema fallback.
- `SeverityCalculatorTest` — modifier composition, clamping, named regression cases ("Play-signed year-old TeamViewer stays at MEDIUM").
- `IntegritySignalMapperTest` (extended) — every new `remote_interaction.*` kind maps to one of the three new signals; no kind silently dropped.
- `RemoteInteractionFindingsCodecTest` — JSON round-trip via `TelemetryJson`.

Target ≥85% line coverage for new aggregator + scorer code.

### 11.2 Robolectric tests (`:deviceintelligence/src/test/` with Robolectric)

- `A11yAbuseDetector` against shadow A11y services with various capability combinations.
- `RemoteControlAppDetector` package-strategy against `ShadowPackageManager` with planted fixtures (TeamViewer, debug-signed, capability-triple).
- `InputSourceDetector` against `ShadowInputManager` with virtual + physical devices.
- `OverlayDetector` against `ShadowPackageManager` with planted `SYSTEM_ALERT_WINDOW` holders.
- `RemoteInteractionInitProvider` lifecycle — starts on `ContentProvider.onCreate`, registers listeners exactly once, deregisters cleanly.

### 11.3 Instrumented tests (`:deviceintelligence/src/androidTest/`)

- **Per-event UI thread cost**: 10,000 synthetic touch dispatches, total time < 500 µs on a Pixel-class device. `@RequiresDevice("performance")` filter for slow emulators with documented baseline.
- **End-to-end live event**: in-test A11y grant via `UiAutomation.executeShellCommand`, assert `interactionEvents.first { it is A11yServiceEnabled }` within 2 s.
- **End-to-end snapshot**: cold-boot, `awaitPrewarm()`, assert `SessionFindings.remoteInteraction` populated and contains the planted service.
- **Listener cleanup**: simulate process kill, verify no dangling callbacks on relaunch.
- **`registerScreenCaptureCallback`** (API 34+): self-capture, assert `ScreenCaptureStarted(initiatedByHost=true)` fires.

### 11.4 Gradle plugin tests (`:deviceintelligence-gradle/src/test/`)

- `ActivityDispatchVisitorTest` — synthetic Activity classfile fixtures (with / without existing override); assert visitor produces classfiles whose `dispatchTouchEvent` invokes `RemoteInteractionRuntime.onTouchEvent` exactly once before existing body / `super`. Snapshot-style disassembly comparison.
- `FrameworkCallSiteVisitorTest` — class with `MediaProjectionManager.createScreenCaptureIntent` and overlay `addView` call sites is rewritten; classes under `android.*`/`androidx.*`/`io.ssemaj.deviceintelligence.*` are NOT.
- `IsInstrumentableFilterTest` — pre-filter returns false for non-Activity classes / excluded prefixes.
- `GradleRunner` end-to-end — builds a synthetic Android module via Gradle TestKit; asserts produced classes-jar contains rewritten classes for Activity samples and untouched classes for excludes. Catches AGP-version-compat regressions.
- `ConsumerRulesValidationTest` — runs R8 full mode over a fixture app; asserts runtime entry points survive shrinking.

### 11.5 Macrobenchmark

A new `:deviceintelligence-microbench` module (or extend an existing benchmark module) asserts §10.1 budgets in CI: cold-start delta, per-event allocation (0 bytes for clean events via `AllocationCounter`), build-time delta on fixture project. Regressions fail CI.

### 11.6 Sample app additions

- `samples/host-app` — new "Security Inspector" screen subscribing to `interactionEvents` with a live timeline + current `SessionFindings.remoteInteraction`.
- `samples/redteam-helper` — fake "remote-control app" APK with the capability triple but benign payload, for sideloading onto a test device.
- `samples/minimal-integration` — 30-line integration showing `interactionEvents.filter { it.severity == HIGH }.collect { abortSensitiveFlow() }`.

### 11.7 CTF roadmap correlation

Slots between Flag 5 (1.0.0) and a new **Flag 6 — Remote Interaction & A11y Abuse** for 1.2.0. Red-team artifacts: fake-RAT APK, ADB-keyboard injection script, Frida script using `dispatchGesture`. Each capability-profile / per-event input / screen-capture signal gets its own validation entry.

### 11.8 Test fixtures

`src/test/resources/interaction/`:

- `manifests/` — synthetic `AndroidManifest.xml` fixtures (clean app, capability-triple app, just-A11y app).
- `allowlist/` — versioned allowlist fixtures (`v1_valid.json`, `v1_missing_signers.json`, `v2_unknown_schema.json`).
- `bytecode/` — pre-compiled `.class` files for `ActivityDispatchVisitorTest`, checked in to avoid CI dependence on a working Java compiler.

---

## 12. Rollout

- **1.2.0**: ship full detector family; bytecode pass on by default; allowlist v1 bundled. New sample screen. CHANGELOG entry, README detector-table update, new `docs/DETECTORS.md` section.
- **1.2.1+**: allowlist updates (asset-only patches don't require runtime changes). RAT package list maintenance.
- **1.3.0**: add Flag 6 CTF red-team artifacts; extend capability-profile heuristics based on observed false-positive reports.
- **2.0.0** (future): if runtime entry-point signatures need to change, that's the trigger.

---

## 13. Open questions

These need a decision before implementation but don't block the design:

1. **Where does `samples/redteam-helper` live?** Existing red-team artifacts referenced in `project_ctf_roadmap.md` are under `tools/` — should the fake-RAT APK go there, or as a fourth `samples/*` module?
2. **Macrobenchmark module placement** — extend an existing benchmark module if one exists; otherwise add `:deviceintelligence-microbench`. Quick check on benchmark conventions before scaffolding.
3. **Capability-profile cache TTL** — proposed 30 seconds keyed on `PackageManager` `lastUpdateTime`. Worth a sanity check against real-world `PackageManager` mutation rates on noisy enterprise devices.
4. **Allowlist signer source-of-truth** — for the initial `interaction_allowlist.v1.json`, signer hashes need to come from somewhere. Proposal: a one-time `tools/build_allowlist.kt` script that pulls signers from Play Store via `apkpure` mirrors and pins them; documented in the asset's header comment. Decide before first build.
