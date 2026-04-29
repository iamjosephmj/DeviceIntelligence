package io.ssemaj.deviceintelligence.internal

import android.os.Process
import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * `runtime.cloner` — App-cloner / multi-app-launcher detector.
 *
 * Drives three native readers in `libdicore.so`
 * (`cloner_probe.cpp`) that pull kernel-truth values out of
 * `/proc/self/{maps,mountinfo,status}` via raw syscalls, then
 * compares them against the corresponding Java-level values that
 * any cloner would have to spoof. A disagreement IS the signal.
 *
 * The three signals are independent; any subset may trip per run:
 *  - `apk_path_mismatch`: a `*.apk` mapping in our address space
 *    does not carry our package name. Catches in-process sandboxes
 *    (Waxmoon, Parallel Space, …) whose host code is mmapped
 *    alongside ours.
 *  - `data_dir_mount_invalid`: either a tmpfs/foreign-source mount
 *    on `/data/.../<our pkg>`, OR our package is missing from the
 *    set of pkg names extractable from data-dir mount-points
 *    (catches the Waxmoon case where we inherit the launcher's
 *    mount namespace via its UID).
 *  - `uid_mismatch`: kernel-real UID disagrees with `Process.myUid()`.
 *    Catches Java-level UID hooks (Frida/Riru/Xposed scripts).
 *
 * Read failures (EACCES, EOF, parse error) silently degrade to
 * "no signal" for that channel; we never escalate a read failure
 * into a finding.
 *
 * Stays declared as `object` for the same JNI-symbol reason as
 * [EmulatorProbe].
 */
internal object ClonerDetector : Detector {

    private const val TAG = "DeviceIntelligence.ClonerDetector"

    override val id: String = "runtime.cloner"

    @Volatile
    private var cached: List<Finding>? = null
    private val lock = Any()

    @JvmStatic private external fun nativeApkPathFromMaps(): String?
    @JvmStatic private external fun nativeForeignApkInMaps(packageName: String): String?
    @JvmStatic private external fun nativeSuspiciousMountFor(packageName: String): String?
    @JvmStatic private external fun nativeDataDirOwnerPackages(): String?
    @JvmStatic private external fun nativeKernelUidFromStatus(): Int

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        if (!ctx.nativeReady) {
            return inconclusive(
                id, "native_not_ready",
                "dicore native lib not loaded", dur(),
            )
        }

        val pkg = ctx.applicationContext.packageName.orEmpty()
        if (pkg.isEmpty()) {
            return inconclusive(
                id, "missing_package_name",
                "context.packageName was null/empty", dur(),
            )
        }

        val findings = synchronized(lock) {
            cached ?: doEvaluate(pkg).also { cached = it }
        }
        return ok(id, findings, dur())
    }

    private fun doEvaluate(pkg: String): List<Finding> {
        val out = ArrayList<Finding>(3)
        val emittedKinds = HashSet<String>(3)

        fun emitOnce(kind: String, severity: Severity, message: String, details: Map<String, String>) {
            if (emittedKinds.add(kind)) {
                out += Finding(
                    kind = kind,
                    severity = severity,
                    subject = pkg,
                    message = message,
                    details = details,
                )
            }
        }

        // ---- Signal 1: apk_path_mismatch ------------------------------------
        val ownApkPath = runCatching { nativeApkPathFromMaps() }
            .onFailure { Log.w(TAG, "nativeApkPathFromMaps threw", it) }
            .getOrNull()
        Log.i(TAG, "raw first apk path from maps: $ownApkPath")

        val foreignApk = runCatching { nativeForeignApkInMaps(pkg) }
            .onFailure { Log.w(TAG, "nativeForeignApkInMaps threw", it) }
            .getOrNull()
        Log.i(TAG, "raw foreign apk for pkg=$pkg: $foreignApk")
        if (foreignApk != null) {
            Log.w(TAG, "apk_path_mismatch(foreign): pkg=$pkg foreign=$foreignApk")
            emitOnce(
                kind = "apk_path_mismatch",
                severity = Severity.CRITICAL,
                message = "Foreign APK mapping detected in process address space",
                details = mapOf(
                    "signal" to "foreign_apk_in_maps",
                    "expected_package" to pkg,
                    "foreign_apk_path" to foreignApk,
                ),
            )
        }
        if (ownApkPath != null && !pathContainsPackageComponent(ownApkPath, pkg)) {
            Log.w(TAG, "apk_path_mismatch(first): pkg=$pkg apkPath=$ownApkPath")
            emitOnce(
                kind = "apk_path_mismatch",
                severity = Severity.CRITICAL,
                message = "Process's first base.apk mapping does not belong to our package",
                details = mapOf(
                    "signal" to "first_apk_mapping",
                    "expected_package" to pkg,
                    "observed_apk_path" to ownApkPath,
                ),
            )
        }

        // ---- Signal 2: data_dir_mount_invalid -------------------------------
        val mountDump = runCatching { nativeSuspiciousMountFor(pkg) }
            .onFailure { Log.w(TAG, "nativeSuspiciousMountFor threw", it) }
            .getOrNull()
        Log.i(TAG, "raw suspicious mount for pkg=$pkg: $mountDump")
        if (mountDump != null) {
            Log.w(TAG, "data_dir_mount_invalid(suspicious): pkg=$pkg dump=$mountDump")
            emitOnce(
                kind = "data_dir_mount_invalid",
                severity = Severity.CRITICAL,
                message = "Suspicious mount touches our data dir (tmpfs or foreign-source)",
                details = mapOf(
                    "signal" to "suspicious_mount",
                    "expected_package" to pkg,
                ) + parseSuspiciousMountDump(mountDump),
            )
        }

        val ownersRaw = runCatching { nativeDataDirOwnerPackages() }
            .onFailure { Log.w(TAG, "nativeDataDirOwnerPackages threw", it) }
            .getOrNull()
        Log.i(TAG, "raw data-dir owner packages: $ownersRaw")
        val owners = ownersRaw?.split('|')?.filter { it.isNotEmpty() }.orEmpty()
        if (owners.isNotEmpty() && pkg !in owners) {
            Log.w(
                TAG,
                "data_dir_mount_invalid(foreign-namespace): " +
                    "pkg=$pkg owners=$owners",
            )
            emitOnce(
                kind = "data_dir_mount_invalid",
                severity = Severity.CRITICAL,
                message = "Process is in a mount namespace that doesn't include our data dir",
                details = mapOf(
                    "signal" to "foreign_mount_namespace",
                    "expected_package" to pkg,
                    "mount_namespace_owners" to owners.joinToString(","),
                ),
            )
        }

        // ---- Signal 3: uid_mismatch -----------------------------------------
        val javaUid = Process.myUid()
        val kernelUid = runCatching { nativeKernelUidFromStatus() }
            .onFailure { Log.w(TAG, "nativeKernelUidFromStatus threw", it) }
            .getOrNull() ?: -1
        Log.i(TAG, "uid: java=$javaUid kernel=$kernelUid")
        if (kernelUid >= 0 && kernelUid != javaUid) {
            Log.w(TAG, "uid_mismatch: java=$javaUid kernel=$kernelUid")
            emitOnce(
                kind = "uid_mismatch",
                severity = Severity.HIGH,
                message = "Kernel-reported UID disagrees with Java-level Process.myUid()",
                details = mapOf(
                    "java_uid" to javaUid.toString(),
                    "kernel_uid" to kernelUid.toString(),
                ),
            )
        }

        Log.i(TAG, "evaluate: ${out.size} finding(s) for pkg=$pkg")
        return out
    }

    /**
     * The native side packs its suspicious-mount dump as
     * `fstype=tmpfs|mount=...|source=...[|host_pkg=...]`. Reuse the
     * common `k=v|k=v` splitter shape.
     */
    private fun parseSuspiciousMountDump(raw: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (kv in raw.split('|')) {
            val eqIdx = kv.indexOf('=')
            if (eqIdx <= 0) continue
            out[kv.substring(0, eqIdx)] = kv.substring(eqIdx + 1)
        }
        return out
    }

    /**
     * True if [path] contains [pkg] as a `/`-or-`-`-bounded
     * component. Mirrors the C++ helper in `cloner_probe.cpp` so
     * both sides agree on what "this path belongs to package X"
     * means.
     */
    private fun pathContainsPackageComponent(path: String, pkg: String): Boolean {
        if (pkg.isEmpty()) return false
        var idx = 0
        while (true) {
            val hit = path.indexOf(pkg, idx)
            if (hit < 0) return false
            val leftOk = hit == 0 || path[hit - 1] == '/'
            val rightIdx = hit + pkg.length
            val rightOk = rightIdx == path.length ||
                path[rightIdx] == '/' || path[rightIdx] == '-'
            if (leftOk && rightOk) return true
            idx = hit + 1
        }
    }

    /** Test-only: drop the cached findings so the next [evaluate] re-runs the native probes. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
