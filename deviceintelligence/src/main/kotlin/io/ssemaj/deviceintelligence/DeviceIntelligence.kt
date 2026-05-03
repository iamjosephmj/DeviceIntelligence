package io.ssemaj.deviceintelligence

import android.content.Context
import io.ssemaj.deviceintelligence.internal.Critical
import io.ssemaj.deviceintelligence.internal.PrewarmCoordinator
import io.ssemaj.deviceintelligence.internal.StackGuard
import io.ssemaj.deviceintelligence.internal.TelemetryCollector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Public entry-point for DeviceIntelligence.
 *
 * DeviceIntelligence is a *telemetry* layer: it collects facts about
 * the runtime environment of the host app (APK integrity, emulator
 * characteristics, app-cloner indicators, hardware key attestation,
 * runtime-environment tampering, root indicators) and hands them
 * back as a single structured [TelemetryReport]. It does NOT decide
 * whether the app should keep running, prompt the user, lock data,
 * or anything else. That decision belongs to the consumer's backend
 * or in-app policy layer.
 *
 * ## Threading
 *
 * The primary entry point is the [collect] `suspend` function — call
 * it from any coroutine and it dispatches the work onto
 * [Dispatchers.IO] for you. For long-running observation (e.g.
 * watching `integrity.art` for a runtime Frida attach), use
 * [observe] which emits a fresh [TelemetryReport] on a configurable
 * interval and cancels with its enclosing scope.
 *
 * For Java consumers and synchronous boundaries (worker threads,
 * unit tests, JNI bridges) use [collectBlocking] / [collectJsonBlocking].
 *
 * ## Pre-warm
 *
 * The library auto-runs a background pre-warm `collect()` at process
 * start (via a manifest-merged `ContentProvider`). This populates
 * per-detector caches so the first user-visible call returns in
 * single-digit ms. To consume the pre-warm result instead of racing
 * it, call [awaitPrewarm] — it returns the in-flight pre-warm if
 * one exists, otherwise runs a fresh collect.
 *
 * ## Cost
 *
 * Typically ~tens of milliseconds on a warm process (one APK ZIP
 * walk dominates `integrity.apk`, attestation results are cached).
 * Cold collect after a process restart can be a few hundred ms on
 * older devices. Each detector caches what it sensibly can; the
 * one explicit exception is `integrity.art`, which re-evaluates on
 * every call so a post-launch Frida attach can't hide behind a
 * frozen verdict.
 */
public object DeviceIntelligence {

    /**
     * The published library version this build was packaged under.
     *
     * Sourced from `BuildConfig.LIBRARY_VERSION`, which is fed at
     * build time from the `VERSION_NAME` Gradle property in
     * `gradle.properties`. JitPack rewrites that property to match
     * the git tag on tag builds, so a JitPack-published artifact
     * reports exactly its Maven coordinate version here. Local
     * development builds report whatever `VERSION_NAME` is checked
     * in.
     *
     * Surfaces in [TelemetryReport.libraryVersion]. Backends use
     * this to detect schema-version skew across a fleet.
     */
    @JvmField
    public val VERSION: String = BuildConfig.LIBRARY_VERSION

    // ---------------------------------------------------------------------
    // Suspend entry points (primary surface)
    // ---------------------------------------------------------------------

    /**
     * Run every registered detector and return a [TelemetryReport]
     * reflecting the current runtime state.
     *
     * Dispatches the underlying work onto [Dispatchers.IO] so it's
     * safe to call from any coroutine context, including
     * `Dispatchers.Main`.
     *
     * Cancellation: if the enclosing coroutine is cancelled
     * mid-collect, the currently-running detector finishes (the
     * library does not interrupt JNI calls or `/proc` reads), and
     * the call resumes with a [kotlinx.coroutines.CancellationException]
     * before the next detector starts.
     */
    @Critical
    public suspend fun collect(context: Context): TelemetryReport {
        StackGuard.verify("DeviceIntelligence.collect")
        return collect(context, CollectOptions.DEFAULT)
    }

    /**
     * Variant of [collect] that filters which detectors run. See
     * [CollectOptions] for the filter semantics.
     */
    @Critical
    public suspend fun collect(context: Context, options: CollectOptions): TelemetryReport {
        StackGuard.verify("DeviceIntelligence.collect")
        val appCtx = context.applicationContext
        return withContext(Dispatchers.IO) {
            TelemetryCollector.collect(appCtx, options)
        }
    }

    /**
     * Convenience wrapper around [collect] that hands back the
     * report serialised to its canonical JSON form.
     */
    @Critical
    public suspend fun collectJson(context: Context): String {
        StackGuard.verify("DeviceIntelligence.collectJson")
        return collect(context).toJson()
    }

    /**
     * Returns the in-flight background pre-warm result, if one is
     * currently being computed. If no pre-warm is in flight (either
     * because the
     * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider]
     * pre-warm has already finished, or the consumer is calling
     * after the prewarm window), this transparently runs a fresh
     * [collect] using [CollectOptions.DEFAULT].
     *
     * Use this when you want the early `app.attestation` data on a
     * splash screen / first-frame UI without spending a redundant
     * collect: the pre-warm is going to run regardless of whether
     * you await it, so awaiting it is free.
     */
    @Critical
    public suspend fun awaitPrewarm(context: Context): TelemetryReport {
        StackGuard.verify("DeviceIntelligence.awaitPrewarm")
        return PrewarmCoordinator.startOrAwait(context).await()
    }

    /**
     * Emits a fresh [TelemetryReport] every [interval], starting
     * with one immediately. The flow runs on [Dispatchers.IO] and
     * stops when its enclosing coroutine scope is cancelled.
     *
     * Designed for the runtime-tampering observation pattern — pair
     * with `CollectOptions(only = setOf("integrity.art"))` to keep
     * each emission cheap when the rest of the report would be
     * wasted work:
     *
     * ```kotlin
     * DeviceIntelligence
     *     .observe(context, 2.seconds, CollectOptions(only = setOf("integrity.art")))
     *     .onEach { report ->
     *         val artFinding = report.detectors
     *             .firstOrNull { it.id == "integrity.art" }
     *             ?.findings?.firstOrNull()
     *         if (artFinding != null) reportToBackend(artFinding)
     *     }
     *     .launchIn(lifecycleScope)
     * ```
     *
     * The [interval] is the *gap between emissions*, not the period:
     * if a single `collect()` takes 500 ms and the interval is 2 s,
     * the next emission is ~2.5 s after the previous one started.
     */
    @Critical
    public fun observe(
        context: Context,
        interval: Duration = 2.seconds,
        options: CollectOptions = CollectOptions.DEFAULT,
    ): Flow<TelemetryReport> {
        // StackGuard.verify is invoked per emission rather than per
        // observe() call so a hooker that wraps the upstream
        // collector at any point during the flow's lifetime gets
        // caught — the observe() call itself returns synchronously,
        // but the hookable surface is the suspend-`produce` lambda.
        val appCtx = context.applicationContext
        return observeFlow(interval) { TelemetryCollector.collect(appCtx, options) }
            .onEach { StackGuard.verify("DeviceIntelligence.observe") }
            .flowOn(Dispatchers.IO)
    }

    /**
     * Builds the polling [Flow] used by [observe], decoupled from
     * the production `produce` lambda so JVM unit tests can pin
     * the timing / cancellation contract without spinning up a
     * real Context.
     *
     * Note: deliberately does NOT call [flowOn] — callers in
     * production add `.flowOn(Dispatchers.IO)`, callers in tests
     * leave it on the test dispatcher so virtual time advances.
     */
    @JvmSynthetic
    internal fun observeFlow(
        interval: Duration,
        produce: suspend () -> TelemetryReport,
    ): Flow<TelemetryReport> = flow {
        while (currentCoroutineContext().isActive) {
            emit(produce())
            delay(interval)
        }
    }

    /**
     * Cumulative session-level view of [observe]'s emissions.
     *
     * Where [observe] hands you a fresh [TelemetryReport] on every
     * tick (each emission is a snapshot — findings that were
     * present last tick but aren't present this tick simply
     * disappear), [observeSession] aggregates findings ACROSS
     * ticks and tags each one with first/last-seen times,
     * observation count, and a [TrackedFinding.stillActive] flag.
     *
     * Use this when:
     *  - You want a UI that never loses sight of a finding the
     *    moment it stops appearing in the latest collect (e.g. a
     *    Frida hook that fires once during onboarding and then
     *    detaches — your UI should still show it for the rest of
     *    the session).
     *  - You need to know how long ago a signal first appeared
     *    (`firstSeenAtEpochMs`), how many collects it survived
     *    (`observationCount`), or whether it's currently active
     *    (`stillActive`).
     *
     * The session begins on first collection of the returned
     * Flow. Cancelling the collector and re-subscribing starts a
     * NEW session — that's how a "Reset" button is implemented:
     * cancel the current scope, re-launch.
     *
     * Two findings are considered the same session entry iff
     * `(detectorId, kind, subject)` matches. See [TrackedFinding]
     * for the full identity contract. Message and details refresh
     * on every re-observation; identity does not.
     *
     * Identical [interval] / [options] semantics to [observe].
     *
     * Example:
     * ```kotlin
     * lifecycleScope.launch {
     *     DeviceIntelligence.observeSession(this@MainActivity, 2.seconds)
     *         .collect { session ->
     *             render(session.findings)  // a List<TrackedFinding>
     *             updateBadge(session.collectionsObserved)
     *         }
     * }
     * ```
     */
    @Critical
    public fun observeSession(
        context: Context,
        interval: Duration = 2.seconds,
        options: CollectOptions = CollectOptions.DEFAULT,
    ): Flow<SessionFindings> {
        // The `observe` we layer on top of already runs
        // StackGuard.verify per emission AND switches to
        // Dispatchers.IO. We don't need to redo either — the
        // upstream's onEach + flowOn carry through `.map`-style
        // transformations.
        return observeSessionFlow(observe(context, interval, options))
    }

    /**
     * Pure aggregator wrapper, decoupled from `observe()` so JVM
     * unit tests can drive the aggregator with a synthetic
     * [Flow] of [TelemetryReport] without spinning up a Context
     * or a polling timer.
     *
     * A fresh [SessionFindingsAggregator] is constructed inside
     * the [flow] builder, which means every `collect()` of the
     * returned Flow gets its own session state. Two collectors
     * of the same returned Flow do NOT share aggregation — each
     * sees its own first-seen / last-seen / observation counts.
     */
    @JvmSynthetic
    internal fun observeSessionFlow(
        upstream: Flow<TelemetryReport>,
    ): Flow<SessionFindings> = flow {
        val aggregator = SessionFindingsAggregator(System.currentTimeMillis())
        upstream.collect { report ->
            emit(aggregator.ingest(report))
        }
    }

    // ---------------------------------------------------------------------
    // Blocking entry points (Java consumers, synchronous boundaries)
    // ---------------------------------------------------------------------

    /**
     * Synchronous variant of [collect] for Java callers and
     * synchronous boundaries (worker threads, unit tests, JNI
     * bridges). Blocks the calling thread; do NOT call from
     * `Dispatchers.Main` or the Android UI thread.
     *
     * Internally uses [runBlocking] so detector implementations
     * that touch coroutine machinery compose cleanly.
     */
    @JvmStatic
    @JvmOverloads
    @Critical
    public fun collectBlocking(
        context: Context,
        options: CollectOptions = CollectOptions.DEFAULT,
    ): TelemetryReport {
        StackGuard.verify("DeviceIntelligence.collectBlocking")
        return runBlocking { collect(context, options) }
    }

    /**
     * Synchronous variant of [collectJson]. Blocks the calling
     * thread; do NOT call from `Dispatchers.Main`.
     */
    @JvmStatic
    @Critical
    public fun collectJsonBlocking(context: Context): String {
        StackGuard.verify("DeviceIntelligence.collectJsonBlocking")
        return runBlocking { collectJson(context) }
    }
}
