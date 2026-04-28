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
 * F16 — In-process runtime-environment detector.
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

    override val id: String = "F16.runtime_environment"

    private const val KIND_DEBUGGER = "debugger_attached"
    private const val KIND_DEBUGGABLE_MISMATCH = "ro_debuggable_mismatch"
    private const val KIND_HOOK_FRAMEWORK = "hook_framework_present"
    private const val KIND_RWX_MAPPING = "rwx_memory_mapping"

    @Volatile
    private var cached: List<Finding>? = null
    private val lock = Any()

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        val findings = synchronized(lock) {
            cached ?: doEvaluate(ctx).also { cached = it }
        }
        Log.i(TAG, "F16 ran: ${findings.size} finding(s)")
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
        // detector consistent with F12/F13 (Kotlin never touches
        // procfs in this codebase).
        if (ctx.nativeReady) {
            val mapsContent = runCatching { NativeBridge.procSelfMaps() }
                .getOrNull()
            if (mapsContent != null) {
                val scan = MapsParser.parse(mapsContent)
                hookFrameworkFindings(pkg, scan).forEach { out += it }
                rwxMappingFinding(pkg, scan)?.let { out += it }
            }
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
     */
    private fun rwxMappingFinding(pkg: String, scan: MapsParser.ScanResult): Finding? {
        if (scan.rwxRegions.isEmpty()) return null
        val details = LinkedHashMap<String, String>()
        details["region_count"] = scan.rwxRegions.size.toString()
        scan.rwxRegions.forEachIndexed { idx, region ->
            details["region_$idx"] = region
        }
        return Finding(
            kind = KIND_RWX_MAPPING,
            severity = Severity.HIGH,
            subject = pkg,
            message = "Read-write-executable memory mapping(s) detected in process address space",
            details = details,
        )
    }

    /** Test-only: drop the cached verdict so the next [evaluate] re-runs. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
