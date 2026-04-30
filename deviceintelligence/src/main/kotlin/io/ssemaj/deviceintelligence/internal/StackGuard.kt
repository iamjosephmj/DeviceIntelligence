package io.ssemaj.deviceintelligence.internal

/**
 * G5 — deterministic call-stack verification at public API
 * entry points.
 *
 * Every method annotated [Critical] (today: the six top-level
 * entries on [io.ssemaj.deviceintelligence.DeviceIntelligence])
 * calls [verify] as its first action. We snapshot
 * `Throwable().stackTrace`, walk it bottom-up, and check each
 * frame's class against an allowlist of "this is a frame we
 * expect to legitimately appear above us". Frames outside the
 * allowlist are recorded; the next `runtime.environment`
 * evaluate observes them via [snapshot] and lifts each one
 * into a `stack_foreign_frame` finding.
 *
 * The check is cheap (~2-5 µs per call): no I/O, no allocation
 * beyond the synthetic Throwable + the ArrayList holding any
 * actual violations.
 *
 * The reason we use a synthetic [Throwable] instead of
 * [Thread.currentThread]`.stackTrace` is that the latter is
 * implemented inside ART and is exactly the place a hooker most
 * reliably trampolines. A `new Throwable()` constructor is
 * compiled into our own `.text` and resolved via the GOT we
 * already verify in G4, making it materially harder to bypass
 * StackGuard without also tripping a higher-severity finding.
 *
 * **Storage semantics — deliberately snapshot, not drain.** The
 * pending store is append-only with deduplication and an upper
 * bound; every successful [verify] or [recordWatchdogViolation]
 * adds at most one new entry, and [snapshot] reads the current
 * contents without removing them. This is a security-tool
 * decision rather than a coding convenience: a foreign frame
 * once observed is a permanent fact about the process, and a
 * concurrent reader (e.g. a background pre-warm collect that
 * runs in parallel with an explicit consumer collect) must NOT
 * be able to "consume" the violation away from the explicit
 * collect's report. Drain semantics created exactly that race
 * — see commit history for the verification logs that revealed
 * it.
 *
 * Deduplication key is `(hookedMethod, className, methodName,
 * lineNumber, source)`, which collapses the typical pattern
 * "the same Frida-script frame appears on the stack of every
 * collect() invocation" down to one finding. The cap
 * ([MAX_PENDING]) protects long-running processes from
 * unbounded growth if an attacker churns hook frames; once
 * full, the oldest entry is evicted (FIFO).
 */
internal object StackGuard {

    /**
     * One captured violation. [hookedMethod] is the
     * `<class>.<method>` of the [Critical] entry that triggered
     * the check; [foreignFrame] is the offending stack frame.
     */
    data class Violation(
        val hookedMethod: String,
        val foreignFrame: StackTraceElement,
        val source: String,
    )

    /**
     * Class-name prefixes that, when seen anywhere on the stack
     * above a [Critical] entry point, are recorded as violations.
     *
     * This is a denylist (rather than allowlist) because the
     * legitimate caller of our public API is, by definition, the
     * consumer's own app — we can't know its package name at
     * library-build time, so any allowlist would either
     * false-positive every legitimate call (rejecting
     * `com.example.app.*`) or be too permissive to be useful.
     *
     * Membership is conservative: every entry is the well-known
     * package of a real Android in-process method-hooking
     * framework. A legitimate non-hooker app whose code happens
     * to live under one of these packages doesn't exist in the
     * wild; a class name match is, by itself, a strong signal of
     * the named framework being active in our process.
     *
     * Backends pivoting on the resulting `stack_foreign_frame`
     * findings can read `details.foreign_class` to identify
     * which framework was seen.
     */
    private val HOOKER_PREFIXES: List<String> = listOf(
        // Xposed family (original Xposed, EdXposed, LSPosed)
        "de.robv.android.xposed",
        "org.lsposed.lspd",
        "org.lsposed.lspatch",
        // YAHFA / SandHook (used by EdXposed and standalone)
        "lab.galaxy.yahfa",
        "com.swift.sandhook",
        // Pine / Whale
        "top.canyie.pine",
        "com.taobao.android.dexposed",
        "com.alibaba.android.epic",
        "me.weishu.epic",
        // Riru / Zygisk
        "com.elderdrivers.riru",
        "io.github.lsposed.lspatch",
        "io.github.libxposed",
        // Frida (gadget-injected agent)
        "re.frida",
        // Substrate / Cydia ports
        "com.saurik.substrate",
        // Misc frameworks seen in the wild
        "io.va.exposed",
        "com.qihoo.magic",   // 360-OS sandbox
        "com.lody.virtual",  // VirtualApp
        "com.lbe.parallel",  // Parallel Space
    )

    /**
     * Hard cap on the pending store. Picked to comfortably hold
     * the steady-state population (every `@Critical` entry × every
     * unique foreign frame above it) on a heavily-hooked process
     * without forcing eviction; well under the megabyte mark of
     * memory the [Violation] objects themselves consume.
     */
    private const val MAX_PENDING: Int = 256

    private val lock = Any()
    // ArrayDeque + dedup-set instead of ConcurrentLinkedQueue: we
    // want O(1) FIFO eviction at the cap AND O(1) "have I already
    // recorded this exact frame?" check. The lock is held only
    // for the dedup test + insert (constant-time), so contention
    // between concurrent verify() and snapshot() is negligible.
    private val pending = ArrayDeque<Violation>(MAX_PENDING)
    private val pendingKeys = HashSet<String>(MAX_PENDING * 2)

    /**
     * Run a stack check. [hookedMethod] is the fully-qualified
     * caller (e.g. `DeviceIntelligence.collect`). Records one
     * [Violation] for every frame whose class matches a known
     * hooking-framework prefix. Never throws.
     *
     * Frame 0 is `verify` itself and frame 1 is the [Critical]
     * caller — both are in our own package and trivially can't
     * match the denylist; we still skip them so the indexing in
     * any future deeper-walk variant is consistent.
     */
    fun verify(hookedMethod: String) {
        val frames: Array<StackTraceElement> = try {
            Throwable().stackTrace
        } catch (t: Throwable) {
            // Catch the unlikely scenario where Throwable creation
            // itself was hooked to throw. We can't do anything but
            // skip the check; the absence of a recorded violation
            // here is itself an audit signal in the higher-level
            // F18 ART-integrity layer.
            return
        }
        for (i in 2 until frames.size) {
            val frame = frames[i]
            if (!matchesHookerPrefix(frame.className)) continue
            recordInternal(
                Violation(
                    hookedMethod = hookedMethod,
                    foreignFrame = frame,
                    source = "stackguard",
                )
            )
        }
    }

    /**
     * Returns an immutable snapshot of every distinct [Violation]
     * recorded since process start (subject to the FIFO eviction
     * at [MAX_PENDING]). Does NOT remove entries — see the
     * class-level KDoc for the rationale (concurrent collects
     * race on a shared queue if they consume).
     *
     * Designed to be called from
     * `RuntimeEnvironmentDetector.evaluate()`; safe to call from
     * any thread.
     */
    fun snapshot(): List<Violation> {
        synchronized(lock) {
            if (pending.isEmpty()) return emptyList()
            return ArrayList(pending)
        }
    }

    /**
     * Sampler entry point used by [StackWatchdog]. Same store,
     * different `source` field. Lives here rather than in
     * StackWatchdog so the store stays single-owner — the only
     * producers are [verify] (deterministic) and this method
     * (sampled), and the only consumer is [snapshot].
     */
    fun recordWatchdogViolation(v: Violation) {
        recordInternal(v)
    }

    /**
     * Inserts a violation into the pending store, deduplicating
     * by stable key and evicting the oldest entry FIFO if the
     * store is at capacity. Held under [lock] so the dedup-check
     * + insert is atomic.
     */
    private fun recordInternal(v: Violation) {
        val key = violationKey(v)
        synchronized(lock) {
            if (!pendingKeys.add(key)) return
            if (pending.size >= MAX_PENDING) {
                val evicted = pending.removeFirst()
                pendingKeys.remove(violationKey(evicted))
            }
            pending.addLast(v)
        }
    }

    private fun violationKey(v: Violation): String =
        v.hookedMethod + '|' +
            v.foreignFrame.className + '|' +
            v.foreignFrame.methodName + '|' +
            v.foreignFrame.lineNumber + '|' +
            v.source

    /** Test-only: drop all pending violations without surfacing them. */
    fun clearForTest() {
        synchronized(lock) {
            pending.clear()
            pendingKeys.clear()
        }
    }

    private fun matchesHookerPrefix(className: String): Boolean {
        for (prefix in HOOKER_PREFIXES) {
            if (className.startsWith(prefix)) return true
        }
        return false
    }
}
