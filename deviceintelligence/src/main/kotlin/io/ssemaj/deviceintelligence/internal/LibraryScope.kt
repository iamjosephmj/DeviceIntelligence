package io.ssemaj.deviceintelligence.internal

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * Process-lifetime [CoroutineScope] owned by the library.
 *
 * Used by:
 *  - [DeviceIntelligenceInitProvider] to launch the background
 *    pre-warm `collect()` without forcing the consumer to thread a
 *    scope through.
 *  - [PrewarmCoordinator] as the carrier scope for the in-flight
 *    pre-warm `Deferred`.
 *
 * Properties of the chosen scope:
 *
 *  - [SupervisorJob]: a single failing pre-warm doesn't cancel
 *    sibling work. The library deliberately swallows pre-warm
 *    failures (caller never sees them — `collect()` is synchronous
 *    on the failure path) so a supervised job is the safe choice.
 *  - [Dispatchers.Default]: the work is CPU-bound (JSON encoding,
 *    SHA-256 over the APK, `/proc/self/maps` parsing). The
 *    underlying [TelemetryCollector] also dispatches its own JNI
 *    calls and short I/O reads, but those are individually cheap.
 *    The public `suspend collect()` overrides this with an explicit
 *    `withContext(Dispatchers.IO)` because the *whole* call has more
 *    blocking I/O than CPU.
 *
 * Lifetime: this scope lives for the process lifetime. There is no
 * `cancel()` API surfaced because the only cancellation event we
 * care about (process death) tears the scope down for free.
 */
internal object LibraryScope : CoroutineScope by CoroutineScope(
    SupervisorJob() + Dispatchers.Default,
)
