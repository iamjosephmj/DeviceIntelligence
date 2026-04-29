package io.ssemaj.deviceintelligence.internal

import android.content.Context
import io.ssemaj.deviceintelligence.TelemetryReport
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Coordinates the single in-flight pre-warm `collect()` so that:
 *
 *  - [DeviceIntelligenceInitProvider] can fire-and-forget kick off
 *    a background pre-warm at process start.
 *  - The public `DeviceIntelligence.awaitPrewarm()` can return the
 *    *same* [TelemetryReport] instance the pre-warm is computing,
 *    instead of spending a redundant collect.
 *  - Subsequent `awaitPrewarm()` calls after completion launch a
 *    fresh pre-warm rather than handing back a stale snapshot.
 *
 * The coordinator only memoizes an *in-flight* [Deferred]. Once
 * that deferred completes (success or failure), the next call
 * launches a new one — `awaitPrewarm()` is documented as "the
 * latest pre-warm result", not "a cached result for the lifetime
 * of the process". For the everyday "single process-start
 * pre-warm + occasional consumer-driven collects" pattern this
 * means awaitPrewarm() is fast for the early window after process
 * start and falls back to a fresh collect afterwards.
 *
 * Caching of *individual detector* state lives inside each
 * detector (e.g. `ApkIntegrityDetector.cachedFingerprint`,
 * `KeyAttestationDetector.lastResult`) — the pre-warm's value is
 * mostly in populating those caches, not in returning the report
 * itself.
 */
internal object PrewarmCoordinator {

    private val mutex = Mutex()
    private var inFlight: Deferred<TelemetryReport>? = null

    /**
     * Returns the in-flight pre-warm [Deferred] if one exists and
     * hasn't finished yet, otherwise launches a fresh collect on
     * [LibraryScope] with [Dispatchers.IO] and remembers it.
     *
     * Callers typically `.await()` the returned deferred. The init
     * provider drops the result on the floor.
     */
    suspend fun startOrAwait(context: Context): Deferred<TelemetryReport> {
        return mutex.withLock {
            val current = inFlight
            if (current != null && current.isActive) {
                current
            } else {
                val appCtx = context.applicationContext
                LibraryScope
                    .async(Dispatchers.IO) { TelemetryCollector.collect(appCtx) }
                    .also { inFlight = it }
            }
        }
    }
}
