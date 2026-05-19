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
