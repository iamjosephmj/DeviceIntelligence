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
 * `runtime.root` — Root indicator detector.
 *
 * Filesystem-, shell-, and installed-app-level root signals. None
 * of these are individually authoritative — every one of them can
 * be hidden by a sufficiently determined root tool (Magisk's
 * DenyList, Zygisk modules, etc.) — so this detector is best
 * thought of as the "low-hanging fruit" layer that pairs with
 * `attestation.key`'s TEE-attested `verified_boot_state` (which
 * is much harder to spoof) and `runtime.environment`'s
 * hooking-framework checks. A device that trips `runtime.root`
 * is a device whose owner did not even bother to hide the root.
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
 *     can strip it via `tools:node="remove"`; `runtime.root` then
 *     silently degrades to channels 1-4.
 *
 * All checks emit at most one finding per match. A single device
 * with `su` in three locations + Magisk + Magisk Manager installed
 * produces five findings (one per channel hit + one per matched
 * file / package), not one big bag.
 */
internal object RootIndicatorsDetector : Detector {

    private const val TAG = "DeviceIntelligence.RootIndicators"

    override val id: String = "runtime.root"

    private const val KIND_SU_BINARY = "su_binary_present"
    private const val KIND_MAGISK = "magisk_artifact_present"
    private const val KIND_TEST_KEYS = "test_keys_build"
    private const val KIND_WHICH_SU = "which_su_succeeded"
    private const val KIND_ROOT_APP = "root_manager_app_installed"

    /**
     * Magisk artifact visible in PID 1's mount namespace. `/proc/1/mountinfo`
     * reads init's mount namespace, which Shamiko (the LSPosed module that
     * hides Magisk from targeted apps) cannot patch — Shamiko operates by
     * unsharing the per-process mount namespace of the target app, not by
     * modifying init. A `magisk` substring in `/proc/1/mountinfo` while
     * `/proc/self/mountinfo` looks clean is a strong "Magisk + Shamiko is
     * hiding from us specifically" signal.
     */
    private const val KIND_MAGISK_INIT_MNT = "magisk_in_init_mountinfo"

    /**
     * The Magisk daemon registers an abstract Unix socket named
     * `@magisk_daemon` (i.e. `\0magisk_daemon` in the kernel's abstract
     * namespace). It is visible to any process in the same network/IPC
     * namespace via `/proc/self/net/unix`. Shamiko hides filesystem
     * artifacts but cannot hide abstract sockets the daemon is actively
     * bound to — the socket is bound in init's network namespace and
     * surfaces in every process's view of the namespace.
     */
    private const val KIND_MAGISK_DAEMON_SOCKET = "magisk_daemon_socket_present"

    /**
     * tmpfs bind-mounted over `/apex/com.android.conscrypt` — the Magisk
     * "MagiskTrustUserCerts"-family module technique that swaps the
     * system TLS trust store with one that accepts user-installed roots.
     * The signal *itself* is TLS-MITM-enabling: any HTTPS the app makes
     * after this mount is in place is interceptable by whoever holds the
     * user-installed cert (Burp / Charles / mitmproxy / etc.).
     *
     * Severity is CRITICAL because this is active TLS interception
     * enablement, not just "root tool present".
     */
    private const val KIND_TLS_TRUST_TAMPERED = "tls_trust_store_tampered"

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
     * host app doesn't otherwise have visibility on, and
     * `runtime.root` degrades gracefully to its on-disk + shell
     * signals.
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
        Log.i(TAG, "ran: ${findings.size} finding(s)")
        return ok(id, findings, dur())
    }

    private fun doEvaluate(ctx: DetectorContext): List<Finding> {
        val pkg = ctx.applicationContext.packageName.orEmpty()
        val out = ArrayList<Finding>(8)

        val suPaths = findSuBinaryPaths()
        suPaths.forEach { out += suBinaryFinding(pkg, it) }

        val magiskHits = findMagiskArtifacts()
        magiskHits.forEach { out += magiskFinding(pkg, it) }

        // Shamiko-aware cross-checks: signals that survive even when
        // a Magisk hide-module has stripped the per-process mountinfo
        // and filesystem-artifact set we'd otherwise rely on.
        readInitMountinfo()?.let { content ->
            parseInitMountinfo(content).forEach { out += magiskInInitMountFinding(pkg, it) }
        }
        readUnixSocketTable()?.let { content ->
            if (parseMagiskDaemonSocket(content)) {
                out += magiskDaemonSocketFinding(pkg)
            }
        }
        readSelfMountinfo()?.let { content ->
            parseConscryptTmpfsMount(content).forEach { out += tlsTrustTamperedFinding(pkg, it) }
        }

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

    /**
     * Pure helper: scan `/proc/1/mountinfo` content for Magisk
     * artefacts. Returns one descriptor per matching line.
     *
     * `mountinfo` line format (`man 5 proc`):
     * ```
     * 36 35 98:0 /mnt1 /mnt parent shared:1 - ext4 /dev/root rw,errors=continue
     *  ^  ^   ^   ^      ^                        ^      ^
     *  id parent dev root mountpoint               fstype source
     * ```
     * We surface the mount point (column 5) since that's the actionable
     * forensic value. Matching is case-insensitive on the literal
     * substring `magisk`, mirroring [parseMagiskMounts].
     */
    internal fun parseInitMountinfo(initMountinfoContent: String): List<String> {
        val out = ArrayList<String>()
        for (line in initMountinfoContent.lineSequence()) {
            if (line.isEmpty()) continue
            if (!line.contains("magisk", ignoreCase = true)) continue
            val cols = line.split(' ')
            val mountpoint = cols.getOrNull(4).orEmpty()
            if (mountpoint.isNotEmpty()) out += "mountpoint=$mountpoint"
        }
        return out
    }

    /**
     * Pure helper: scan `/proc/self/net/unix` content for the Magisk
     * daemon's abstract Unix socket. Abstract namespace sockets
     * show up with a leading NUL byte, which procfs renders as `@`
     * (e.g. `@magisk_daemon`). Returns true iff such an entry is
     * present.
     *
     * `/proc/net/unix` line format:
     * ```
     * Num       RefCount Protocol Flags    Type St Inode Path
     * ffff...   2        0        10000    0001 01  1234  @magisk_daemon
     * ```
     * We match on the literal substring `@magisk_daemon` — the daemon
     * name has been stable across Magisk versions since v22.
     */
    internal fun parseMagiskDaemonSocket(unixSocketTableContent: String): Boolean {
        for (line in unixSocketTableContent.lineSequence()) {
            if (line.contains("@magisk_daemon")) return true
        }
        return false
    }

    /**
     * Pure helper: scan `/proc/self/mountinfo` content for a tmpfs
     * bind-mount over the Conscrypt APEX directory. This is the
     * MagiskTrustUserCerts technique that swaps Android's system
     * trust store with one accepting user-installed roots — once
     * installed, any HTTPS this app makes is MITM-interceptable.
     *
     * Returns one descriptor per matching line. We require both
     * `/apex/com.android.conscrypt` somewhere in the line AND
     * `tmpfs` as the source filesystem type (column after the `-`
     * separator in `mountinfo`), so a legitimate read-only bind of
     * the conscrypt apex from its actual ext4/erofs backing does
     * not trip.
     */
    internal fun parseConscryptTmpfsMount(selfMountinfoContent: String): List<String> {
        val out = ArrayList<String>()
        for (line in selfMountinfoContent.lineSequence()) {
            if (line.isEmpty()) continue
            if (!line.contains("/apex/com.android.conscrypt")) continue
            // mountinfo separates pre-`-` and post-`-` field groups.
            // The fstype is the first field after the `-` separator.
            val dashIdx = line.indexOf(" - ")
            if (dashIdx < 0) continue
            val postDash = line.substring(dashIdx + 3)
            val fstype = postDash.substringBefore(' ')
            if (fstype != "tmpfs") continue
            // Extract the mount point (column 5, 0-indexed 4) for
            // the descriptor — same as parseInitMountinfo.
            val preDash = line.substring(0, dashIdx)
            val cols = preDash.split(' ')
            val mountpoint = cols.getOrNull(4).orEmpty()
            if (mountpoint.isNotEmpty()) out += "mountpoint=$mountpoint"
        }
        return out
    }

    /**
     * Read PID 1's mount namespace. The path is unreadable on
     * heavily-locked-down devices where this process doesn't have
     * `CAP_SYS_PTRACE` or PID 1's mount namespace is hidden via
     * `hidepid`; any failure degrades silently to "no signal" — we
     * never escalate a read failure into a finding.
     */
    private fun readInitMountinfo(): String? = readProcFile("/proc/1/mountinfo")

    /** Read `/proc/self/net/unix`. Same silent-degrade contract as [readInitMountinfo]. */
    private fun readUnixSocketTable(): String? = readProcFile("/proc/self/net/unix")

    /**
     * Read `/proc/self/mountinfo`. Same silent-degrade contract.
     * Note: this differs from the `/proc/mounts` read in
     * [findMagiskArtifacts] — `mountinfo` carries the per-process
     * namespace view and source-fstype field we need for the
     * tmpfs-over-conscrypt check; `/proc/mounts` doesn't.
     */
    private fun readSelfMountinfo(): String? = readProcFile("/proc/self/mountinfo")

    private fun readProcFile(path: String): String? = runCatching {
        val f = File(path)
        if (!f.exists()) return@runCatching null
        f.readText()
    }.onFailure { Log.w(TAG, "$path read failed", it) }.getOrNull()

    private fun magiskInInitMountFinding(pkg: String, descriptor: String): Finding = Finding(
        kind = KIND_MAGISK_INIT_MNT,
        severity = Severity.HIGH,
        subject = pkg,
        message = "Magisk artefact present in /proc/1/mountinfo (Shamiko cannot hide init's mount namespace)",
        details = mapOf("artifact" to descriptor),
    )

    private fun magiskDaemonSocketFinding(pkg: String): Finding = Finding(
        kind = KIND_MAGISK_DAEMON_SOCKET,
        severity = Severity.HIGH,
        subject = pkg,
        message = "Magisk daemon abstract Unix socket @magisk_daemon is bound (visible even when filesystem artefacts are hidden)",
        details = mapOf("socket_name" to "@magisk_daemon"),
    )

    private fun tlsTrustTamperedFinding(pkg: String, descriptor: String): Finding = Finding(
        kind = KIND_TLS_TRUST_TAMPERED,
        severity = Severity.CRITICAL,
        subject = pkg,
        message = "tmpfs bind-mount over /apex/com.android.conscrypt — system TLS trust store has been swapped, MITM-enabling",
        details = mapOf("artifact" to descriptor),
    )

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
