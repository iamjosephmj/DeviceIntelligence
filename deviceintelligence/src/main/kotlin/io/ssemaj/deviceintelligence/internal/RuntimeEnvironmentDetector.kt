package io.ssemaj.deviceintelligence.internal

import android.content.pm.ApplicationInfo
import android.os.Debug
import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import java.io.File

/**
 * `runtime.environment` — In-process runtime-environment detector.
 *
 * Surfaces tampering signals that show up *inside our own process*
 * the moment something attaches to or injects into us:
 *  - A debugger / tracer is attached. Catches both the JDWP debugger
 *    (covered by [Debug.isDebuggerConnected]) and any native tracer
 *    attached via `ptrace` (gdb, lldb, frida-trace, strace),
 *    surfaced via the `TracerPid:` line in `/proc/self/status`.
 *  - The app's own `FLAG_DEBUGGABLE` disagrees with the system's
 *    `ro.debuggable`. Either side being lifted from 0 to 1 is the
 *    classic repackaging tell — release APKs from a real Play Store
 *    install always have the flag at 0 and a stock OS always has
 *    `ro.debuggable=0` outside of `userdebug` builds.
 *  - A known userland hooking framework's library is mapped into
 *    our address space (Frida, Substrate, Xposed, LSPosed, Riru,
 *    Zygisk, Taichi). The match list is intentionally narrow: every
 *    entry is a framework whose presence in any production process
 *    is, by itself, a meaningful tampering signal.
 *  - A read-write-executable memory mapping exists in the process.
 *    The Android loader never produces RWX pages — code is RX, data
 *    is RW, ro-data is R. RWX is exclusively the JIT region of an
 *    in-process trampoline / hot-patching engine.
 *
 * All four checks share a single `/proc/self/maps` read (~200-500
 * KB string materialized once via [NativeBridge.procSelfMaps]) and
 * a single `/proc/self/status` read. Result is cached for the
 * process lifetime; all four signals are properties that cannot
 * change while the process runs.
 *
 * Stays declared as `object` to match the rest of the detector
 * fleet's pattern.
 */
internal object RuntimeEnvironmentDetector : Detector {

    private const val TAG = "DeviceIntelligence.RuntimeEnv"

    override val id: String = "runtime.environment"

    private const val KIND_DEBUGGER = "debugger_attached"
    private const val KIND_DEBUGGABLE_MISMATCH = "ro_debuggable_mismatch"
    private const val KIND_HOOK_FRAMEWORK = "hook_framework_present"
    private const val KIND_RWX_MAPPING = "rwx_memory_mapping"

    /**
     * Frida 16+ Gum JIT signature: `/memfd:jit-cache` mapped `rwxp` with
     * region size >8 MB. ART legitimately maps the same path but only
     * with `r-xp`/`r--p` perms, so the combination is unambiguous on
     * Android.
     *
     * Reported as a distinct finding from the generic `rwx_memory_mapping`
     * because it carries higher attribution confidence (specifically
     * Frida, vs. "some hooking framework") — backends that want a
     * Frida-only signal can pivot on this kind without inspecting
     * details.
     */
    private const val KIND_FRIDA_MEMFD_JIT = "frida_memfd_jit_present"

    @Volatile
    private var cached: List<Finding>? = null
    private val lock = Any()

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        // Two-tier findings: the cached half are process-stable
        // facts (debugger attached, RWX page present, hook-framework
        // .so loaded) — once true at process start they stay true,
        // so caching is correct and saves a maps re-read every scan.
        // The live half are native-integrity scans whose outcome
        // can change mid-process (an attacker can mprotect+memcpy
        // .text seconds after start), so they MUST run every call.
        val baseFindings = synchronized(lock) {
            cached ?: doEvaluate(ctx).also { cached = it }
        }
        val liveFindings = doLiveEvaluate(ctx)
        val findings = if (liveFindings.isEmpty()) baseFindings else baseFindings + liveFindings
        Log.i(TAG, "ran: ${findings.size} finding(s) (cached=${baseFindings.size}, live=${liveFindings.size})")
        return ok(id, findings, dur())
    }

    private fun doEvaluate(ctx: DetectorContext): List<Finding> {
        val out = ArrayList<Finding>(4)
        val pkg = ctx.applicationContext.packageName.orEmpty()

        debuggerFinding(pkg)?.let { out += it }
        debuggableMismatchFinding(ctx, pkg)?.let { out += it }

        // Single maps read shared by both the hook and RWX checks.
        // If the native bridge isn't ready, we silently skip both;
        // refusing to read /proc/self/maps from Kotlin keeps this
        // detector consistent with runtime.emulator / runtime.cloner (Kotlin never touches
        // procfs in this codebase).
        if (ctx.nativeReady) {
            val mapsContent = runCatching { NativeBridge.procSelfMaps() }
                .getOrNull()
            if (mapsContent != null) {
                val scan = MapsParser.parse(mapsContent)
                hookFrameworkFindings(pkg, scan).forEach { out += it }
                rwxMappingFinding(pkg, scan)?.let { out += it }
                fridaMemfdJitFinding(pkg, scan)?.let { out += it }
            }
        }

        return out
    }

    /**
     * Live native-integrity probes from `NATIVE_INTEGRITY_DESIGN.md`.
     * Run every call (NOT cached) because their outcomes can change
     * mid-process — an attacker can mprotect+memcpy `.text` long
     * after process start, dlopen a Frida gadget after onboarding,
     * etc.
     *
     * Each Gx layer is independently failure-tolerant: a `null`
     * return from any `NativeBridge.scan*` means that layer is
     * unavailable on this device and produces zero findings. We
     * never crash a `runtime.environment` evaluate because one
     * native subsystem misfired.
     */
    private fun doLiveEvaluate(ctx: DetectorContext): List<Finding> {
        if (!ctx.nativeReady) return emptyList()
        val pkg = ctx.applicationContext.packageName.orEmpty()
        val out = ArrayList<Finding>(4)

        val textRecords = runCatching { NativeBridge.scanTextIntegrity() }.getOrNull()
        if (textRecords != null) {
            for (record in textRecords) {
                NativeIntegrityFindings.textFinding(record, pkg)?.let { out += it }
            }
        }

        val libRecords = runCatching { NativeBridge.scanLoadedLibraries() }.getOrNull()
        if (libRecords != null) {
            Log.i(TAG, "G3 inventory ok loaded_findings=${libRecords.size}")
            for (record in libRecords) {
                NativeIntegrityFindings.loadedLibraryFinding(record, pkg)?.let { out += it }
            }
        }

        val gotRecords = runCatching { NativeBridge.scanGotIntegrity() }.getOrNull()
        if (gotRecords != null) {
            Log.i(TAG, "G4 GOT scan ok flagged=${gotRecords.size}")
            for (record in gotRecords) {
                out += NativeIntegrityFindings.gotIntegrityFindings(record, pkg)
            }
        }

        // G5 + G6 — observe deterministic StackGuard violations
        // (recorded by @Critical entry points) AND sampled
        // StackWatchdog violations (recorded during recent
        // collect() invocations). Both share the same pending
        // store inside StackGuard so a single snapshot pulls
        // both; the `details.source` field on each finding tells
        // backends which producer recorded it.
        //
        // Snapshot semantics (NOT drain): every report includes
        // every distinct violation seen since process start (cap'd
        // by StackGuard's FIFO eviction). This protects the
        // explicit consumer collect from a concurrent background
        // pre-warm collect "consuming" the violations away — once
        // a foreign frame has been seen above us, every report
        // surfaces it.
        val stackViolations = StackGuard.snapshot()
        if (stackViolations.isNotEmpty()) {
            Log.i(TAG, "G5/G6 stackguard snapshot violations=${stackViolations.size}")
            for (v in stackViolations) {
                out += NativeIntegrityFindings.stackForeignFrameFinding(v, pkg)
            }
        }

        // G7 — same snapshot semantics for JNI return-address
        // violations: every report includes every distinct
        // violation seen since process start, irrespective of
        // which other collect() coroutine ran first.
        val callerRecords = runCatching { NativeBridge.snapshotCallerViolations() }.getOrNull()
        if (callerRecords != null && callerRecords.isNotEmpty()) {
            Log.i(TAG, "G7 caller verify snapshot violations=${callerRecords.size}")
            for (record in callerRecords) {
                NativeIntegrityFindings.callerOutOfRangeFinding(record, pkg)?.let { out += it }
            }
        }

        // CTF Flag 1 — runtime DEX injection. Bytecode-level
        // tampering of the running process (InMemoryDexClassLoader
        // and DexClassLoader) which the existing G2-G7 native scans
        // and the integrity.art ART-internals vectors cannot see.
        // The helper owns its own first-call baseline + diff
        // semantics; we just pass through every finding it emits.
        // See [DexInjection] kdoc for channel a/b details.
        val dexFindings = runCatching { DexInjection.scan(ctx) }
            .onFailure { Log.w(TAG, "DexInjection scan threw", it) }
            .getOrNull()
            .orEmpty()
        if (dexFindings.isNotEmpty()) {
            Log.i(TAG, "DEX injection scan emitted ${dexFindings.size} finding(s)")
            out += dexFindings
        }

        return out
    }

    /**
     * Returns a finding when either the JVM-level JDWP debugger is
     * connected or a non-zero TracerPid is reported by procfs. The
     * two sources are complementary: `Debug.isDebuggerConnected`
     * catches the Android Studio debugger but misses native
     * attachers; `TracerPid` catches anything that called `ptrace`
     * but doesn't distinguish between "debugger" and "ptrace-based
     * hook framework attached itself for syscall interception".
     * Both hits are merged into one finding with both signals in
     * `details` so backends can tell them apart without growing the
     * finding-kind vocabulary.
     */
    private fun debuggerFinding(pkg: String): Finding? {
        val jvmAttached = runCatching { Debug.isDebuggerConnected() }.getOrDefault(false)
        val tracerPid = readTracerPid()
        if (!jvmAttached && (tracerPid == null || tracerPid == 0)) return null

        val details = LinkedHashMap<String, String>()
        details["jvm_debugger_connected"] = jvmAttached.toString()
        if (tracerPid != null) {
            details["tracer_pid"] = tracerPid.toString()
        }

        return Finding(
            kind = KIND_DEBUGGER,
            severity = Severity.HIGH,
            subject = pkg,
            message = "Debugger or native tracer is attached to the process",
            details = details,
        )
    }

    /**
     * `TracerPid` is the PID of the process currently `ptrace`-attached
     * to us, or 0 if none. Lives on the third-or-so line of
     * `/proc/self/status` on every Linux kernel Android ships.
     * Returns null when the file can't be read or the field can't
     * be parsed — distinguishes "no tracer" (0) from "lookup
     * failed" (null) so we don't false-positive on read errors.
     */
    private fun readTracerPid(): Int? {
        return try {
            val file = File("/proc/self/status")
            if (!file.exists()) return null
            file.useLines { lines ->
                for (line in lines) {
                    if (line.startsWith("TracerPid:")) {
                        return@useLines line.substringAfter(':').trim().toIntOrNull()
                    }
                }
                null
            }
        } catch (t: Throwable) {
            Log.w(TAG, "TracerPid read failed", t)
            null
        }
    }

    /**
     * Compares two facts that should agree on every clean install:
     *  - Our `applicationInfo.flags & FLAG_DEBUGGABLE` (set at
     *    package-build time, sealed into the manifest of the APK
     *    that's actually running).
     *  - `ro.debuggable` (set at boot by the system; 1 only on
     *    `userdebug` / `eng` builds).
     *
     * On a real Play Store user-build install, the app flag is 0
     * and the prop is 0. A mismatch means either an attacker
     * flipped the manifest at repackage time (debuggable APK on a
     * production OS), or the OS itself was tampered with to expose
     * debugging on a production-tagged release build.
     */
    private fun debuggableMismatchFinding(ctx: DetectorContext, pkg: String): Finding? {
        val appFlag = (ctx.applicationContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val sysProp = runCatching { NativeBridge.systemProperty("ro.debuggable") }
            .getOrNull()
            ?: return null  // can't read prop -> can't compare -> silent
        val sysFlag = sysProp == "1"
        if (appFlag == sysFlag) return null

        return Finding(
            kind = KIND_DEBUGGABLE_MISMATCH,
            severity = Severity.HIGH,
            subject = pkg,
            message = "Application debuggable flag disagrees with system ro.debuggable property",
            details = mapOf(
                "app_debuggable_flag" to appFlag.toString(),
                "ro_debuggable" to sysProp,
            ),
        )
    }

    /**
     * One finding per distinct hooking framework seen. We emit
     * separately rather than as one big finding so a backend can
     * alert / triage on each framework independently (a Frida
     * agent in production is a different ops story than a stale
     * LSPosed module).
     */
    private fun hookFrameworkFindings(pkg: String, scan: MapsParser.ScanResult): List<Finding> {
        if (scan.hookFrameworks.isEmpty()) return emptyList()
        return scan.hookFrameworks.map { fw ->
            Finding(
                kind = KIND_HOOK_FRAMEWORK,
                severity = Severity.HIGH,
                subject = pkg,
                message = "Hook framework library mapped into process address space ($fw)",
                details = mapOf("framework" to fw),
            )
        }
    }

    /**
     * Single finding regardless of how many RWX regions we found —
     * one such region is already a hard signal; the count is in
     * `details.region_count` and the first few descriptors are in
     * `details.region_*` for forensics.
     *
     * On post-API-28 Android the dynamic loader never produces an
     * `rwxp`/`rwxs` mapping, ART's JIT code cache uses dual-mapping
     * (an RX view and a RW view of the same physical pages, never
     * RWX), and ordinary native libraries split into discrete
     * `r-xp` / `rw-p` / `r--p` segments. The remaining producers
     * are almost exclusively in-process hooking frameworks that
     * allocate RWX trampoline pages: LSPosed (via YAHFA / SandHook),
     * Pine, Whale, EdXposed, Riru hookers, Frida's agent, Cydia
     * Substrate, and similar. We therefore classify the finding
     * as a likely hook-trampoline signal in the human-readable
     * message and add a `likely_cause` detail field to make the
     * intent unambiguous to backend reviewers.
     */
    private fun rwxMappingFinding(pkg: String, scan: MapsParser.ScanResult): Finding? {
        if (scan.rwxRegions.isEmpty()) return null
        val details = LinkedHashMap<String, String>()
        details["region_count"] = scan.rwxRegions.size.toString()
        details["likely_cause"] =
            "in-process hooking framework trampoline page " +
                "(LSPosed / YAHFA / SandHook / Pine / Whale / Frida agent / Substrate)"
        scan.rwxRegions.forEachIndexed { idx, region ->
            details["region_$idx"] = region
        }
        return Finding(
            kind = KIND_RWX_MAPPING,
            severity = Severity.HIGH,
            subject = pkg,
            message =
                "Read-write-executable memory mapping detected — strong signature of an " +
                    "in-process hooking framework trampoline (LSPosed/YAHFA/SandHook/Frida " +
                    "agent/Substrate). The Android loader and ART JIT do not produce RWX " +
                    "pages on API 28+; this is the canonical fingerprint left behind when " +
                    "a hooker allocates an RWX page to host its method-redirect trampolines.",
            details = details,
        )
    }

    /**
     * Frida 16+ Gum JIT attribution finding. Fires in addition to the
     * generic [rwxMappingFinding] when the same maps line(s) match the
     * `/memfd:jit-cache` + `rwxp` + `>8 MB` signature — the more
     * specific finding lets backends pivot on Frida-only without
     * inspecting `rwx_memory_mapping`'s `details` map.
     */
    private fun fridaMemfdJitFinding(pkg: String, scan: MapsParser.ScanResult): Finding? {
        if (scan.fridaMemfdJitRegions.isEmpty()) return null
        val details = LinkedHashMap<String, String>()
        details["region_count"] = scan.fridaMemfdJitRegions.size.toString()
        scan.fridaMemfdJitRegions.forEachIndexed { idx, region ->
            details["region_$idx"] = region
        }
        return Finding(
            kind = KIND_FRIDA_MEMFD_JIT,
            severity = Severity.HIGH,
            subject = pkg,
            message =
                "Frida 16+ Gum JIT signature: rwxp-mapped /memfd:jit-cache region(s) > 8 MB. " +
                    "ART legitimately maps the same path but only with r-xp/r--p perms; " +
                    "the rwxp combination is unambiguous on Android.",
            details = details,
        )
    }

    /** Test-only: drop the cached verdict so the next [evaluate] re-runs. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
