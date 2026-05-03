package io.ssemaj.deviceintelligence

/**
 * One [Finding] tracked across the lifetime of a session.
 *
 * Two findings are considered the same — and collapse into a
 * single [TrackedFinding] — when their `(detectorId, kind, subject)`
 * tuple matches. That's the right level of identity for session
 * tracking:
 *
 *  - **Detector id + kind** pin the *type* of signal (e.g.
 *    `runtime.environment`/`hook_framework_present`).
 *  - **Subject** disambiguates multiple instances of the same kind
 *    in one collect (e.g. two distinct `[anon:dalvik-DEX data]`
 *    regions both emit `dex_in_anonymous_mapping`, but their
 *    subjects differ).
 *  - [Finding.message] and [Finding.details] are NOT part of the
 *    identity. They are diagnostic strings that may legitimately
 *    drift between collects (timestamps, address ranges,
 *    severity escalations) without representing a new underlying
 *    signal.
 *
 * [stillActive] is true when this finding was observed in the
 * MOST RECENT [TelemetryReport] ingested by the aggregator. A
 * finding that fired earlier in the session but hasn't appeared
 * in subsequent collects is preserved with `stillActive = false`,
 * so consumers can render it as historical evidence rather than
 * losing it from the UI.
 *
 * @property detectorId Source detector id (e.g. `runtime.environment`).
 * @property finding The most recent observation. Replaced on every
 *   re-observation so the rendered details reflect the newest
 *   message / details map.
 * @property firstSeenAtEpochMs Wall-clock time (from
 *   [TelemetryReport.collectedAtEpochMs]) of the first collect that
 *   surfaced this finding.
 * @property lastSeenAtEpochMs Wall-clock time of the most recent
 *   collect that surfaced this finding. Equal to
 *   [firstSeenAtEpochMs] for findings observed exactly once.
 * @property observationCount How many ingested collects have
 *   surfaced this finding. ≥ 1.
 * @property stillActive `true` iff this finding was present in the
 *   most recent ingested [TelemetryReport].
 */
public data class TrackedFinding(
    public val detectorId: String,
    public val finding: Finding,
    public val firstSeenAtEpochMs: Long,
    public val lastSeenAtEpochMs: Long,
    public val observationCount: Int,
    public val stillActive: Boolean,
)

/**
 * Cumulative session view of findings observed across one or more
 * [TelemetryReport]s.
 *
 * Emitted by [DeviceIntelligence.observeSession]. Each emission is a
 * full snapshot of every finding observed in the session so far —
 * not a delta — so consumers can rebind their entire UI to the
 * latest [SessionFindings] without diffing.
 *
 * Findings are returned in **first-seen order** within
 * [findings], so a UI rendering them in iteration order shows the
 * earliest-observed signals at the top and newest at the bottom
 * (or vice-versa, depending on the consumer's sort).
 *
 * @property latestReport The most-recently-ingested
 *   [TelemetryReport]. Useful for accessing detector status,
 *   collection duration, and per-detector inconclusive / error
 *   reasons that the cumulative [findings] list does not surface.
 * @property findings All findings observed in the session, each
 *   wrapped with first/last-seen times, observation count, and
 *   active state. Findings whose `(detectorId, kind, subject)`
 *   key has not appeared in any ingested collect are not present.
 * @property collectionsObserved Number of [TelemetryReport]s the
 *   aggregator has ingested in this session. Starts at 1 on the
 *   first emission.
 * @property sessionStartedAtEpochMs Wall-clock time the session
 *   began — typically the wall-clock time the
 *   [DeviceIntelligence.observeSession] flow was first collected.
 * @property lastUpdatedAtEpochMs Wall-clock time of the most-recent
 *   ingested report (== `latestReport.collectedAtEpochMs`).
 */
public data class SessionFindings(
    public val latestReport: TelemetryReport,
    public val findings: List<TrackedFinding>,
    public val collectionsObserved: Int,
    public val sessionStartedAtEpochMs: Long,
    public val lastUpdatedAtEpochMs: Long,
) {
    public companion object {
        /** Empty session — used when no reports have been ingested yet. */
        @JvmField
        public val NEVER_OBSERVED: List<TrackedFinding> = emptyList()
    }
}
