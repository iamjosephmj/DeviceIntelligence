package io.ssemaj.deviceintelligence.internal

import android.content.Context
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.Finding

/**
 * Plug-in contract for one fact-collecting layer of DeviceIntelligence.
 *
 * Every detector is responsible for ONE narrow check (apk integrity,
 * emulator probe, app cloner, etc.) and returns a single
 * [DetectorReport]. The orchestrating [TelemetryCollector] only
 * iterates a registered list of these and concatenates their reports
 * into the final [io.ssemaj.deviceintelligence.TelemetryReport] — so adding a new
 * detector is purely additive.
 *
 * Implementation rules:
 *  - MUST NOT throw — wrap any unexpected error and return a
 *    [DetectorStatus.ERROR] report. Throwing breaks the entire
 *    collect call for the consumer.
 *  - SHOULD complete in single-digit milliseconds. Anything more
 *    expensive belongs in a separate background task whose state
 *    this detector only summarises.
 *  - MUST be re-entrant safe; the collector may run detectors
 *    concurrently in a future revision.
 *  - MAY hold per-process cached state. The collector itself does
 *    not cache.
 */
internal interface Detector {

    /**
     * Stable identifier, surfaced as [DetectorReport.id]. Convention
     * is `"F<n>.<short_name>"`, e.g. `"F10.apk_integrity"`.
     */
    val id: String

    /**
     * Inspects the runtime, returns a [DetectorReport]. MUST NOT throw.
     */
    fun evaluate(ctx: DetectorContext): DetectorReport
}

/**
 * Context passed to every detector. Wraps the bits of runtime state
 * a detector might need without making each one re-discover them.
 *
 * [f10Report] carries the F10 ApkIntegrityDetector's [DetectorReport]
 * from the same `collect()` call, populated by [TelemetryCollector]
 * AFTER F10 runs and BEFORE downstream detectors run. Detectors that
 * don't depend on F10's verdict ignore it; F14's
 * [KeyAttestationDetector] uses it to derive the `app_recognition`
 * portion of its TEE-integrity verdict (an F10 finding == "running
 * APK doesn't match build-time fingerprint" => `UNRECOGNIZED_VERSION`).
 *
 * Null means "F10 hasn't run yet in this collect() pass," which the
 * verdict deriver treats as `UNEVALUATED` rather than as a failure.
 */
internal data class DetectorContext(
    val applicationContext: Context,
    val nativeReady: Boolean,
    val f10Report: DetectorReport? = null,
)

/**
 * Convenience: build an OK [DetectorReport] from an [id], a
 * [findings] list, and a duration. Used by [Detector] implementations
 * to keep their bodies focused on probing rather than wrapping.
 */
internal fun ok(id: String, findings: List<Finding>, durationMs: Long): DetectorReport =
    DetectorReport(
        id = id,
        status = DetectorStatus.OK,
        durationMs = durationMs,
        findings = findings,
    )

internal fun inconclusive(
    id: String,
    reason: String,
    message: String,
    durationMs: Long,
): DetectorReport = DetectorReport(
    id = id,
    status = DetectorStatus.INCONCLUSIVE,
    durationMs = durationMs,
    findings = emptyList(),
    inconclusiveReason = reason,
    errorMessage = message,
)

internal fun errored(id: String, t: Throwable, durationMs: Long): DetectorReport =
    DetectorReport(
        id = id,
        status = DetectorStatus.ERROR,
        durationMs = durationMs,
        findings = emptyList(),
        errorMessage = "${t.javaClass.simpleName}: ${t.message ?: "<no message>"}",
    )
