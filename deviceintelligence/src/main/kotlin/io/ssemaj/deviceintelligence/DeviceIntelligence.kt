package io.ssemaj.deviceintelligence

import android.content.Context
import io.ssemaj.deviceintelligence.internal.TelemetryCollector

/**
 * Public entry-point for DeviceIntelligence.
 *
 * DeviceIntelligence is a *telemetry* layer: it collects facts about
 * the runtime environment of the host app (APK integrity, emulator
 * characteristics, app-cloner indicators, hardware key attestation,
 * runtime-environment tampering, root indicators) and hands them back
 * as a single structured [TelemetryReport]. It does NOT decide
 * whether the app should keep running, prompt the user, lock data, or
 * anything else. That decision belongs to the consumer's backend or
 * in-app policy layer.
 *
 * Use [collect] / [collectJson] for one-shot snapshots. Each detector
 * caches what it sensibly can; an outer cache should live in the
 * consumer if a hot-loop pattern is needed. Cost is typically tens
 * of milliseconds (a single APK ZIP walk dominates), safe to call
 * from any thread, but recommend off the main thread for production.
 */
public object DeviceIntelligence {

    /**
     * The published library version this build was packaged under.
     *
     * Sourced from `BuildConfig.LIBRARY_VERSION`, which is fed at build
     * time from the `VERSION_NAME` Gradle property in
     * `gradle.properties`. JitPack rewrites that property to match the
     * git tag on tag builds, so a JitPack-published artifact reports
     * exactly its Maven coordinate version here. Local development
     * builds report whatever `VERSION_NAME` is checked in.
     *
     * Surfaces in [TelemetryReport.libraryVersion]. Backends use this to
     * detect schema-version skew across a fleet.
     */
    @JvmField
    public val VERSION: String = BuildConfig.LIBRARY_VERSION

    /**
     * Run every detector and return a [TelemetryReport] reflecting
     * the current runtime state.
     *
     * Cost: typically ~tens of milliseconds (a single APK ZIP walk
     * dominates). Safe to call from any thread; for production use
     * call off the main thread.
     */
    public fun collect(context: Context): TelemetryReport =
        TelemetryCollector.collect(context.applicationContext)

    /**
     * Convenience wrapper around [collect] that hands back the
     * report serialised to its canonical JSON form. Equivalent to
     * `collect(context).toJson()` but shorter at the call site.
     */
    public fun collectJson(context: Context): String =
        collect(context).toJson()
}
