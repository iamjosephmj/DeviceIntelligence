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
