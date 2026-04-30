package io.ssemaj.deviceintelligence.internal

import android.util.Log

/**
 * G6 — probabilistic call-stack sampler for the
 * [TelemetryCollector.collect] worker thread.
 *
 * StackGuard (G5) gives us a deterministic check at every public
 * API entry point; that catches hooks on the OUTER surface but
 * misses hooks on internal detectors (a Frida script that wraps
 * `MapsParser.parse` or `NativeBridge.scanLoadedLibraries` is
 * invisible to G5 because the user never calls those directly).
 *
 * StackWatchdog fills that gap by spawning a daemon thread for
 * the duration of a `collect()` call. The daemon polls the
 * target thread's stack every [SAMPLE_INTERVAL_MS] and re-uses
 * the same hooker-prefix denylist as [StackGuard]. Each unique
 * `(hookedFrame, foreignFrame.className)` pair is recorded
 * exactly once per scan so a continuously-hooked method doesn't
 * generate one finding per sample.
 *
 * The watchdog is bounded:
 *   - Caps total samples at [MAX_SAMPLES_PER_SCAN] so a long
 *     scan can't run away with thread time.
 *   - Caps recorded violations at [MAX_VIOLATIONS_PER_SCAN]
 *     so a misconfigured device can't return a 100k-element
 *     array.
 *   - Joins the daemon in `finally` with a small grace period;
 *     if the daemon doesn't exit it gets interrupted (the worst
 *     case is that we leak ~one daemon thread per `collect()`,
 *     which is bounded by `collect()` arrival rate — mid-tens
 *     per minute even for the heaviest consumers).
 */
internal object StackWatchdog {

    private const val TAG = "DeviceIntelligence.StackWatchdog"

    /**
     * Sampling cadence. Chosen empirically: short enough to catch
     * a single-detector hook in the per-scan window (most detectors
     * take 1-50 ms each), long enough to keep the watchdog's CPU
     * cost well under 1% of the scan budget.
     */
    private const val SAMPLE_INTERVAL_MS: Long = 100

    /** Hard upper bound on samples per `watchDuring` invocation. */
    private const val MAX_SAMPLES_PER_SCAN: Int = 100

    /**
     * Hard upper bound on UNIQUE foreign-frame violations recorded
     * per `watchDuring` invocation. Past this we silently stop
     * recording (the detector will already know the device is
     * compromised; piling on more findings doesn't add signal).
     */
    private const val MAX_VIOLATIONS_PER_SCAN: Int = 32

    /**
     * Class-name prefixes that, when seen on the target thread's
     * stack, are recorded. Same denylist semantics as [StackGuard]
     * — kept as a separate copy so the two checks can diverge in
     * the future (e.g. StackWatchdog might want to ignore certain
     * hooker frames that legitimately appear during JIT compilation
     * on some OEM forks).
     */
    private val HOOKER_PREFIXES: List<String> = listOf(
        "de.robv.android.xposed",
        "org.lsposed.lspd",
        "org.lsposed.lspatch",
        "lab.galaxy.yahfa",
        "com.swift.sandhook",
        "top.canyie.pine",
        "com.taobao.android.dexposed",
        "com.alibaba.android.epic",
        "me.weishu.epic",
        "com.elderdrivers.riru",
        "io.github.lsposed.lspatch",
        "io.github.libxposed",
        "re.frida",
        "com.saurik.substrate",
        "io.va.exposed",
        "com.qihoo.magic",
        "com.lody.virtual",
        "com.lbe.parallel",
    )

    /**
     * Run [block] under the watchdog. The daemon thread samples
     * [target]'s stack; on completion every unique violation found
     * is queued onto [StackGuard]'s pending store (so
     * `RuntimeEnvironmentDetector.evaluate` lifts both deterministic
     * and sampled findings via the same `StackGuard.snapshot()` call).
     */
    inline fun <T> watchDuring(target: Thread, block: () -> T): T {
        val daemon = startDaemon(target)
        try {
            return block()
        } finally {
            stopDaemon(daemon)
        }
    }

    /**
     * Daemon-thread state. Public so the inline `watchDuring`
     * can pass it into the matching `stopDaemon` without exposing
     * the underlying Thread to callers.
     */
    class WatchdogHandle internal constructor(
        internal val thread: Thread,
        internal val state: WatchdogState,
    )

    /**
     * State the daemon mutates from its own thread and the caller
     * reads in `stopDaemon`. Volatile fields are sufficient — we
     * never read-modify-write across threads.
     */
    class WatchdogState internal constructor(
        @Volatile var stop: Boolean = false,
        @Volatile var samplesTaken: Int = 0,
        @Volatile var violationsRecorded: Int = 0,
    )

    fun startDaemon(target: Thread): WatchdogHandle {
        val state = WatchdogState()
        val seen = HashSet<String>()
        val daemon = Thread({
            while (!state.stop && state.samplesTaken < MAX_SAMPLES_PER_SCAN) {
                try {
                    Thread.sleep(SAMPLE_INTERVAL_MS)
                } catch (ie: InterruptedException) {
                    break
                }
                if (state.stop) break
                state.samplesTaken++
                val frames: Array<StackTraceElement> = try {
                    target.stackTrace
                } catch (t: Throwable) {
                    continue
                }
                if (state.violationsRecorded >= MAX_VIOLATIONS_PER_SCAN) continue
                for (frame in frames) {
                    if (state.violationsRecorded >= MAX_VIOLATIONS_PER_SCAN) break
                    if (!matchesHookerPrefix(frame.className)) continue
                    val dedupKey = frame.className + "#" + frame.methodName
                    if (!seen.add(dedupKey)) continue
                    state.violationsRecorded++
                    StackGuard.recordWatchdogViolation(
                        StackGuard.Violation(
                            hookedMethod = "TelemetryCollector.collect",
                            foreignFrame = frame,
                            source = "watchdog_sample",
                        )
                    )
                }
            }
        }, "DeviceIntelligence-StackWatchdog")
        daemon.isDaemon = true
        daemon.start()
        return WatchdogHandle(daemon, state)
    }

    fun stopDaemon(handle: WatchdogHandle) {
        handle.state.stop = true
        handle.thread.interrupt()
        try {
            handle.thread.join(SAMPLE_INTERVAL_MS * 2)
        } catch (ie: InterruptedException) {
            // Restoring the interrupt flag is not useful here —
            // stopDaemon is called from a `finally` block and the
            // caller's intent is already to exit.
        }
        Log.i(
            TAG,
            "G6 watchdog stopped samples=${handle.state.samplesTaken} " +
                "violations=${handle.state.violationsRecorded}"
        )
    }

    private fun matchesHookerPrefix(className: String): Boolean {
        for (prefix in HOOKER_PREFIXES) {
            if (className.startsWith(prefix)) return true
        }
        return false
    }
}
