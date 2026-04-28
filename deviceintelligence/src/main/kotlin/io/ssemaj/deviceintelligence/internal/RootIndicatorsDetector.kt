package io.ssemaj.deviceintelligence.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import java.io.File

/**
 * F17 — Root indicator detector.
 *
 * Filesystem-, shell-, and installed-app-level root signals. None
 * of these are individually authoritative — every one of them can
 * be hidden by a sufficiently determined root tool (Magisk's
 * DenyList, Zygisk modules, etc.) — so this detector is best
 * thought of as the "low-hanging fruit" layer that pairs with
 * F14's TEE-attested `verified_boot_state` (which is much harder
 * to spoof) and F16's hooking-framework checks. A device that
 * trips F17 is a device whose owner did not even bother to hide
 * the root.
 *
 * Five orthogonal channels:
 *  1. `su` binary on disk: walk `$PATH` plus the canonical
 *     hardcoded paths (`/sbin/su`, `/system/bin/su`, etc.).
 *  2. Magisk artifacts: file/dir existence + `/proc/mounts` scan.
 *  3. `ro.build.tags == test-keys`: indicates a non-release ROM,
 *     a hand-edited build.prop, or an old Android Cupcake-era
 *     development build.
 *  4. `which su` fallthrough: spawn `Runtime.exec("which su")`
 *     ONLY when channel 1 came up empty. The check is ~30-80ms
 *     versus single-digit ms for everything else, but it catches
 *     `su` binaries placed in PATH directories we didn't enumerate
 *     (rare but real on heavily customized ROMs).
 *  5. Known root-manager app installed: `PackageManager.getPackageInfo`
 *     against a hardcoded list. Works on Android 11+ thanks to the
 *     `QUERY_ALL_PACKAGES` permission declared in the library manifest.
 *     Consumers who cannot justify that permission under Play policy
 *     can strip it via `tools:node="remove"`; F17 then silently
 *     degrades to channels 1-4.
 *
 * All checks emit at most one finding per match. A single device
 * with `su` in three locations + Magisk + Magisk Manager installed
 * produces five findings (one per channel hit + one per matched
 * file / package), not one big bag.
 */
internal object RootIndicatorsDetector : Detector {

    private const val TAG = "DeviceIntelligence.RootIndicators"

    override val id: String = "F17.root_indicators"

    private const val KIND_SU_BINARY = "su_binary_present"
    private const val KIND_MAGISK = "magisk_artifact_present"
    private const val KIND_TEST_KEYS = "test_keys_build"
    private const val KIND_WHICH_SU = "which_su_succeeded"
    private const val KIND_ROOT_APP = "root_manager_app_installed"

    /**
     * Hardcoded paths checked for an `su` binary regardless of
     * whether they appear in `$PATH`. Mirrors the standard list
     * every public root-detector library (RootBeer, etc.) walks;
     * captured here rather than depending on RootBeer to keep the
     * SDK dependency-free.
     */
    private val HARDCODED_SU_PATHS: List<String> = listOf(
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/data/local/tmp/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        "/cache/su",
    )

    /**
     * Magisk-shipped paths and files. The first three are the
     * stable Magisk install locations (have moved historically
     * but every recent version uses these); `magisk.db` is the
     * config DB (older naming). Mount-table scan is separate
     * because Magisk's "magisk" overlay can be reflected only via
     * `/proc/mounts`, not via filesystem existence.
     */
    private val MAGISK_PATHS: List<String> = listOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/data/adb/magisk.db",
        "/data/data/com.topjohnwu.magisk",
    )

    /**
     * Specific package names checked via [PackageManager.getPackageInfo].
     *
     * Visibility on Android 11+ is provided by the
     * `android.permission.QUERY_ALL_PACKAGES` declaration in the
     * library manifest, which gives `getPackageInfo` / `getInstalledPackages`
     * access to every installed package without needing to maintain
     * per-package `<queries>` entries.
     *
     * Consumers who cannot justify QUERY_ALL_PACKAGES under Google
     * Play's permitted-use-case policy can strip the permission via
     * `tools:node="remove"`; see the library manifest comment for
     * the exact incantation. With the permission stripped these
     * lookups silently return "not installed" for any package the
     * host app doesn't otherwise have visibility on, and F17
     * degrades gracefully to its on-disk + shell signals.
     */
    private val ROOT_MANAGER_PACKAGES: List<String> = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.kingouser.com",
        "com.kingoapp.apk",
        "me.weishu.kernelsu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
    )

    @Volatile
    private var cached: List<Finding>? = null
    private val lock = Any()

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        val findings = synchronized(lock) {
            cached ?: doEvaluate(ctx).also { cached = it }
        }
        Log.i(TAG, "F17 ran: ${findings.size} finding(s)")
        return ok(id, findings, dur())
    }

    private fun doEvaluate(ctx: DetectorContext): List<Finding> {
        val pkg = ctx.applicationContext.packageName.orEmpty()
        val out = ArrayList<Finding>(8)

        val suPaths = findSuBinaryPaths()
        suPaths.forEach { out += suBinaryFinding(pkg, it) }

        val magiskHits = findMagiskArtifacts()
        magiskHits.forEach { out += magiskFinding(pkg, it) }

        testKeysFinding(pkg, ctx)?.let { out += it }

        // Fallthrough: only spend the ~30-80ms `which su` cost when
        // the cheap file-existence walk found nothing. If we already
        // have su hits, `which` would just confirm them.
        if (suPaths.isEmpty()) {
            whichSuFinding(pkg)?.let { out += it }
        }

        rootManagerAppFindings(pkg, ctx).forEach { out += it }

        return out
    }

    /**
     * Walks the hardcoded path list plus every entry in `$PATH`,
     * returns each path that resolves to an existing file. We don't
     * try to verify it's actually executable or actually a "real"
     * `su`; existence at one of these paths in a release-mode user
     * app is already evidence enough.
     */
    private fun findSuBinaryPaths(): List<String> {
        val seen = LinkedHashSet<String>()
        for (p in HARDCODED_SU_PATHS) {
            if (existsSafely(p)) seen += p
        }
        val pathEnv = runCatching { System.getenv("PATH") }.getOrNull().orEmpty()
        if (pathEnv.isNotEmpty()) {
            for (dir in pathEnv.split(':')) {
                if (dir.isEmpty()) continue
                val candidate = if (dir.endsWith('/')) "${dir}su" else "$dir/su"
                if (candidate !in seen && existsSafely(candidate)) {
                    seen += candidate
                }
            }
        }
        return seen.toList()
    }

    /**
     * Combined file-system + mount-table scan for Magisk artifacts.
     * Returns one descriptor per hit, with the descriptor format
     * `path=<path>` for filesystem hits and `mount=<mountpoint>`
     * for mount-table hits.
     */
    private fun findMagiskArtifacts(): List<String> {
        val out = ArrayList<String>()
        for (p in MAGISK_PATHS) {
            if (existsSafely(p)) out += "path=$p"
        }
        runCatching {
            val mounts = File("/proc/mounts")
            if (mounts.exists()) {
                val content = mounts.readText()
                out.addAll(parseMagiskMounts(content))
            }
        }.onFailure { Log.w(TAG, "/proc/mounts scan failed", it) }
        return out
    }

    /**
     * Pure helper extracted for testability. Walks `/proc/mounts`
     * line-by-line, returning a `mount=<target>` descriptor for
     * each line whose source / target / fstype mentions `magisk`
     * (case-insensitive).
     *
     * Mount-table line format is fixed by `man 5 fstab`:
     * ```
     * device  mountpoint  fstype  options  freq  passno
     * ```
     * We surface the target (column 2) since it's the most
     * actionable forensic value.
     */
    internal fun parseMagiskMounts(mountsContent: String): List<String> {
        val out = ArrayList<String>()
        for (line in mountsContent.lineSequence()) {
            if (line.isEmpty()) continue
            if (!line.contains("magisk", ignoreCase = true)) continue
            val cols = line.split(' ')
            val target = cols.getOrNull(1).orEmpty()
            if (target.isNotEmpty()) out += "mount=$target"
        }
        return out
    }

    private fun suBinaryFinding(pkg: String, path: String): Finding = Finding(
        kind = KIND_SU_BINARY,
        severity = Severity.HIGH,
        subject = pkg,
        message = "An `su` binary was found at a known root-tool path",
        details = mapOf("path" to path),
    )

    private fun magiskFinding(pkg: String, descriptor: String): Finding = Finding(
        kind = KIND_MAGISK,
        severity = Severity.HIGH,
        subject = pkg,
        message = "Magisk-related artifact present on device",
        details = mapOf("artifact" to descriptor),
    )

    /**
     * `test-keys` in `ro.build.tags` historically meant the build was
     * signed with the AOSP test signing keys; on every modern OEM
     * release ROM this value is `release-keys`. A `test-keys` value
     * on a production device almost always means a custom ROM, an
     * engineering build, or a hand-edited build.prop.
     */
    private fun testKeysFinding(pkg: String, ctx: DetectorContext): Finding? {
        if (!ctx.nativeReady) return null
        val tags = runCatching { NativeBridge.systemProperty("ro.build.tags") }
            .getOrNull()
            ?: return null
        if (!tags.contains("test-keys")) return null
        return Finding(
            kind = KIND_TEST_KEYS,
            severity = Severity.MEDIUM,
            subject = pkg,
            message = "ro.build.tags reports a test-keys signed build (custom ROM or eng build)",
            details = mapOf("ro_build_tags" to tags),
        )
    }

    /**
     * `which su` as a last-resort. Spawning a process is expensive
     * (~30-80ms) so we only call this when [findSuBinaryPaths] came
     * up empty. Captures `su` binaries in PATH directories we didn't
     * hardcode (rare, but real on heavily customized ROMs).
     *
     * Reads the first line of stdout; non-empty + exit==0 means
     * `which` resolved a path. We deliberately avoid `Runtime.exec`'s
     * `waitFor()`-without-timeout footgun by giving it a hard cap.
     */
    private fun whichSuFinding(pkg: String): Finding? {
        val process = runCatching {
            ProcessBuilder("which", "su")
                .redirectErrorStream(true)
                .start()
        }.getOrNull() ?: return null
        return try {
            val finished = process.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!finished) {
                process.destroyForcibly()
                return null
            }
            val output = process.inputStream.bufferedReader().use { it.readLine() }.orEmpty().trim()
            if (process.exitValue() != 0 || output.isEmpty()) return null
            Finding(
                kind = KIND_WHICH_SU,
                severity = Severity.HIGH,
                subject = pkg,
                message = "`which su` resolved to a binary not on the standard hardcoded path list",
                details = mapOf("which_output" to output),
            )
        } catch (t: Throwable) {
            Log.w(TAG, "which su check failed", t)
            null
        }
    }

    /**
     * One finding per installed root-manager app. We tolerate
     * NameNotFoundException as the "not installed" case (vast
     * majority of devices) and only log other throwables — a
     * SecurityException on a wonky ROM should not nuke the whole
     * detector.
     */
    private fun rootManagerAppFindings(pkg: String, ctx: DetectorContext): List<Finding> {
        val pm = ctx.applicationContext.packageManager
        val out = ArrayList<Finding>()
        for (candidate in ROOT_MANAGER_PACKAGES) {
            val present = isPackageInstalled(pm, candidate)
            if (!present) continue
            out += Finding(
                kind = KIND_ROOT_APP,
                severity = Severity.MEDIUM,
                subject = pkg,
                message = "Known root-manager / Xposed-manager app is installed on the device",
                details = mapOf("package_name" to candidate),
            )
        }
        return out
    }

    private fun isPackageInstalled(pm: PackageManager, name: String): Boolean = try {
        pm.getPackageInfo(name, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (t: Throwable) {
        Log.w(TAG, "getPackageInfo($name) threw", t)
        false
    }

    /**
     * `File.exists` can throw [SecurityException] under SELinux on
     * some ROMs (we get "permission denied" rather than "not
     * found"). Treat any exception as "not found" — false negatives
     * are acceptable here, false positives are not.
     */
    private fun existsSafely(path: String): Boolean = try {
        File(path).exists()
    } catch (_: SecurityException) {
        false
    } catch (t: Throwable) {
        Log.w(TAG, "File($path).exists() threw", t)
        false
    }

    /** Test-only: drop the cached verdict so the next [evaluate] re-runs. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
