package io.ssemaj.deviceintelligence

/**
 * Stateful aggregator that turns a stream of [TelemetryReport]s
 * into a stream of cumulative [SessionFindings] snapshots.
 *
 * Public because consumers may want to drive the aggregation
 * themselves — for example, a UI that funnels both periodic
 * `observe()` ticks and explicit "Re-collect" button presses
 * through one shared session. The Flow-based wrapper
 * [DeviceIntelligence.observeSession] uses this internally; it
 * is the right choice when you only have one source of reports.
 *
 * Pure Kotlin / pure logic — no Android, no coroutine machinery.
 *
 * Identity: two findings are the same iff
 * `(detectorId, kind, subject)` matches. See [TrackedFinding] for
 * the rationale.
 *
 * Insertion order: [LinkedHashMap] preserves first-seen order, so
 * the [SessionFindings.findings] list is naturally chronological.
 *
 * Not thread-safe: each instance is intended to be driven by a
 * single coroutine. The `flow {}` wrapper provides that contract
 * automatically (`collect` is sequential within one collector).
 */
public class SessionFindingsAggregator(
    private val sessionStartedAtEpochMs: Long,
) {

    private val tracked = LinkedHashMap<String, TrackedFinding>()
    private var collectionsObserved: Int = 0

    /**
     * Folds [report] into the running session state and returns
     * the resulting [SessionFindings] snapshot. Mutates internal
     * state — calling [ingest] twice with the same input does NOT
     * produce the same output (observation counts increment).
     *
     * Not thread-safe: each instance is intended to be driven by a
     * single coroutine / single thread.
     */
    public fun ingest(report: TelemetryReport): SessionFindings {
        collectionsObserved += 1
        val now = report.collectedAtEpochMs

        // Walk the new report and compute its key set in one pass,
        // upserting tracked entries as we go. Keys-in-this-report
        // is the basis for marking previously-seen findings as
        // inactive after the loop.
        val keysInReport = HashSet<String>()
        for (det in report.detectors) {
            for (finding in det.findings) {
                val key = identityKey(det.id, finding)
                keysInReport += key
                val existing = tracked[key]
                tracked[key] = if (existing == null) {
                    TrackedFinding(
                        detectorId = det.id,
                        finding = finding,
                        firstSeenAtEpochMs = now,
                        lastSeenAtEpochMs = now,
                        observationCount = 1,
                        stillActive = true,
                    )
                } else {
                    existing.copy(
                        // Refresh the embedded Finding so consumers see the
                        // newest message / details / severity. Identity is
                        // preserved by the unchanged map key.
                        finding = finding,
                        lastSeenAtEpochMs = now,
                        observationCount = existing.observationCount + 1,
                        stillActive = true,
                    )
                }
            }
        }

        // Anything tracked but missing from this report flips to
        // inactive. We don't drop these — keeping them lets the UI
        // render historical evidence (a Frida hook that fired ten
        // seconds ago and disappeared is still meaningful signal).
        for ((key, entry) in tracked) {
            if (key !in keysInReport && entry.stillActive) {
                tracked[key] = entry.copy(stillActive = false)
            }
        }

        return SessionFindings(
            latestReport = report,
            findings = tracked.values.toList(),
            collectionsObserved = collectionsObserved,
            sessionStartedAtEpochMs = sessionStartedAtEpochMs,
            lastUpdatedAtEpochMs = now,
        )
    }

    public companion object {
        /**
         * Stable identity key. Matches the contract on
         * [TrackedFinding]: detector + kind + subject only;
         * message / details fluctuations don't shift identity.
         *
         * Subject is normalised to empty string when null so
         * `(det, kind, null)` and `(det, kind, "")` collapse to
         * the same key. Exposed (rather than left private) so
         * downstream consumers and tests can compute the same
         * key the aggregator uses internally — useful for
         * deduping on the consumer side or for cross-aggregator
         * comparisons.
         */
        @JvmStatic
        public fun identityKey(detectorId: String, finding: Finding): String =
            "$detectorId|${finding.kind}|${finding.subject.orEmpty()}"
    }
}
