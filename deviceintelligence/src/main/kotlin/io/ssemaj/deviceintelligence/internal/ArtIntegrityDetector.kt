package io.ssemaj.deviceintelligence.internal

import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * `integrity.art` — In-process ART manipulation detector.
 *
 * Catches five orthogonal classes of runtime ART tampering that
 * `runtime.environment` (which only scans `/proc/self/maps` for
 * known framework names + RWX pages) cannot see:
 *
 *  - **Vector A — ArtMethod entry-point rewrite**: every Java
 *    method's `entry_point_from_quick_compiled_code_` slot is the
 *    primary tool every Xposed-family hooker (Xposed, EdXposed,
 *    LSPosed, YAHFA, Pine, SandHook, Whale) uses to redirect
 *    execution. We snapshot the entry pointers of ~10 frozen
 *    methods at `JNI_OnLoad`, and on each evaluate compare them
 *    both against the snapshot (catches transient hooks that
 *    patched-then-restored) and against an expected set of
 *    libart / boot.oat / JIT-cache ranges (catches whatever's
 *    currently installed regardless of when it was installed).
 *
 *  - **Vector C — JNIEnv function-table tamper**: Frida-Java
 *    rewrites `JNIEnv->functions->GetMethodID` and friends to
 *    intercept JNI calls. Same snapshot+range machinery as
 *    Vector A.
 *
 *  - **Vector D — inline trampoline on ART hot-paths**: modern
 *    Frida `Interceptor.attach` patches the prologue bytes of
 *    `art::JNI::CallStaticIntMethod`, `art_quick_invoke_stub`,
 *    etc. We extract a per-Android-version baseline at SDK
 *    development time, embed it as `const` data, and at runtime
 *    snapshot+compare the prologue bytes for ~10 ART hot-path
 *    targets.
 *
 *  - **Vector E — entry_point_from_jni_ rewrite**: closes Vector
 *    A's blind spot for Frida-Java's `cls.method.implementation =`
 *    style hooks. Frida-Java does not touch
 *    `entry_point_from_quick_compiled_code_`; instead it overwrites
 *    the `data_` slot (which for native methods is
 *    `entry_point_from_jni_`) with its bridge function. Snapshot +
 *    diff + classification mirrors Vector A's machinery.
 *
 *  - **Vector F — ACC_NATIVE bit flip**: the most reliable
 *    Frida-Java fingerprint. For non-native Java methods the
 *    `ACC_NATIVE` bit in `access_flags_` is unset; Frida-Java
 *    flips it ON to redirect dispatch through the JNI bridge.
 *    Java methods do not legitimately become native at runtime,
 *    so a 0→1 transition is a binary, unambiguous tamper signal.
 *
 * Each vector emits its own finding kinds:
 *  - `art_method_entry_out_of_range` (HIGH) — Vector A
 *  - `art_method_entry_drifted` (HIGH) — Vector A
 *  - `jni_env_table_out_of_range` (HIGH) — Vector C
 *  - `jni_env_table_drifted` (HIGH) — Vector C
 *  - `art_internal_prologue_drifted` (HIGH) — Vector D
 *  - `art_internal_prologue_baseline_mismatch` (MEDIUM) — Vector D
 *  - `art_method_jni_entry_drifted` (HIGH) — Vector E
 *  - `art_method_jni_entry_out_of_range` (HIGH) — Vector E
 *  - `art_method_acc_native_flipped_on` (HIGH) — Vector F
 *  - `art_method_acc_native_flipped_off` (HIGH) — Vector F
 *
 * Caching: intentionally **none**. `integrity.art` re-evaluates
 * on every `DI.collect()` call. A cached per-process verdict
 * would let any Frida / LSPosed / Zygisk attach that landed
 * *after* the first collect (the common case for runtime
 * injection — debugger attaches, dynamic-analysis frameworks,
 * "frida-trace -U" against a long-running app) hide forever
 * behind a frozen pre-attach verdict. The full scan is ~50 field
 * reads + 5 SHA-256s on tiny buffers (~15 ms in practice), so
 * re-running on every collect is the right default. Consumers
 * that need a stricter perf budget should rate-limit
 * `DI.collect()` itself; this detector deliberately does not
 * memoize across calls.
 */
internal object ArtIntegrityDetector : Detector {

    private const val TAG = "DeviceIntelligence.ArtIntegrity"

    /** Sentinel returned by `NativeBridge.artIntegrityProbe()` when the unit is present. */
    private const val PROBE_ALIVE_SENTINEL: Int = 0xF18A11FE.toInt()

    /** Vector A — entry pointer escaped libart/boot.oat/jit_cache. */
    internal const val KIND_ART_METHOD_ENTRY_OUT_OF_RANGE = "art_method_entry_out_of_range"

    /** Vector A — entry pointer drifted vs the stable baseline. */
    internal const val KIND_ART_METHOD_ENTRY_DRIFTED = "art_method_entry_drifted"

    /** Vector A — the mmap-protected baseline page was tampered with between scans. */
    internal const val KIND_ART_BASELINE_TAMPERED = "art_baseline_tampered"

    /** Vector C — JNIEnv function-table pointer escaped libart's RX segment. */
    internal const val KIND_JNI_ENV_TABLE_OUT_OF_RANGE = "jni_env_table_out_of_range"

    /** Vector C — JNIEnv function-table pointer drifted vs the JNI_OnLoad snapshot. */
    internal const val KIND_JNI_ENV_TABLE_DRIFTED = "jni_env_table_drifted"

    /** Vector C — the JNIEnv-table baseline page was tampered with between scans. */
    internal const val KIND_JNI_ENV_BASELINE_TAMPERED = "jni_env_baseline_tampered"

    /** Vector D — libart prologue bytes drifted vs the JNI_OnLoad snapshot. */
    internal const val KIND_ART_INTERNAL_PROLOGUE_DRIFTED = "art_internal_prologue_drifted"

    /** Vector D — libart prologue bytes mismatch the embedded per-API baseline. */
    internal const val KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH =
        "art_internal_prologue_baseline_mismatch"

    /** Vector D — the inline-prologue baseline page was tampered with between scans. */
    internal const val KIND_ART_INTERNAL_PROLOGUE_BASELINE_TAMPERED =
        "art_internal_prologue_baseline_tampered"

    /** Vector E — entry_point_from_jni_ drifted vs the JNI_OnLoad snapshot (Frida-Java). */
    internal const val KIND_ART_METHOD_JNI_ENTRY_DRIFTED = "art_method_jni_entry_drifted"

    /** Vector E — entry_point_from_jni_ points outside known ART memory regions. */
    internal const val KIND_ART_METHOD_JNI_ENTRY_OUT_OF_RANGE =
        "art_method_jni_entry_out_of_range"

    /** Vector E — the JNI-entry baseline page was tampered with between scans. */
    internal const val KIND_ART_METHOD_JNI_ENTRY_BASELINE_TAMPERED =
        "art_method_jni_entry_baseline_tampered"

    /** Vector F — ACC_NATIVE bit flipped 0→1 (Frida-Java hook on non-native method). */
    internal const val KIND_ART_METHOD_ACC_NATIVE_FLIPPED_ON =
        "art_method_acc_native_flipped_on"

    /** Vector F — ACC_NATIVE bit flipped 1→0 (rare reverse tamper). */
    internal const val KIND_ART_METHOD_ACC_NATIVE_FLIPPED_OFF =
        "art_method_acc_native_flipped_off"

    /** Vector F — the access-flags baseline page was tampered with between scans. */
    internal const val KIND_ART_METHOD_ACCESS_FLAGS_BASELINE_TAMPERED =
        "art_method_access_flags_baseline_tampered"

    override val id: String = "integrity.art"

    /**
     * Serialises concurrent `evaluate()` calls so we don't race
     * two native scans through the mmap-protected snapshot pages
     * (each scan unprotects → reads → reprotects; concurrent
     * scans would briefly leave a window writable to the wrong
     * thread). NOT a verdict cache — see the class kdoc on why
     * `integrity.art` deliberately doesn't memoize.
     */
    private val lock = Any()

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        val findings = synchronized(lock) { doEvaluate(ctx) }
        Log.i(TAG, "ran: ${findings.size} finding(s)")
        return ok(id, findings, dur())
    }

    private fun doEvaluate(ctx: DetectorContext): List<Finding> {
        if (!ctx.nativeReady) {
            Log.w(TAG, "native bridge unavailable; integrity.art returns empty findings")
            return emptyList()
        }
        val probe = runCatching { NativeBridge.artIntegrityProbe() }
            .onFailure { Log.w(TAG, "artIntegrityProbe call failed", it) }
            .getOrNull()
        if (probe != PROBE_ALIVE_SENTINEL) {
            Log.w(
                TAG,
                "artIntegrityProbe returned 0x%08x (expected 0x%08x); integrity.art native unit not linked"
                    .format(probe ?: 0, PROBE_ALIVE_SENTINEL),
            )
            return emptyList()
        }

        val pkg = ctx.applicationContext.packageName.orEmpty()
        val registrySize = runCatching { NativeBridge.artIntegrityRegistrySize() }
            .getOrNull() ?: 0
        val resolved = runCatching { NativeBridge.artIntegrityRegistryResolved() }
            .getOrNull() ?: 0
        val readable = runCatching { NativeBridge.artIntegrityEntryPointReadable() }
            .getOrNull() ?: 0
        val rangeCounts = runCatching { NativeBridge.artIntegrityRangeCounts() }.getOrNull()
        val rangeSummary = rangeCounts?.let {
            "libart=${it.getOrElse(0) { 0 }} bootOAT=${it.getOrElse(1) { 0 }} " +
                "jit=${it.getOrElse(2) { 0 }} otherOAT=${it.getOrElse(3) { 0 }}"
        } ?: "unavailable"
        Log.i(
            TAG,
            "status: resolved=$resolved/$registrySize entry_readable=$readable ranges=$rangeSummary",
        )

        return runVectorA(pkg) + runVectorC(pkg) + runVectorD(pkg) +
            runVectorE(pkg) + runVectorF(pkg)
    }

    /**
     * Vector A — re-reads the ArtMethod entry pointer for each
     * registry slot, classifies the live address against the
     * known ART memory regions captured by M3, and emits findings:
     *
     *  - `art_method_entry_out_of_range` (HIGH) — live entry escapes
     *    every known region. Catches "currently hooked".
     *  - `art_method_entry_drifted` (HIGH) — live differs from
     *    snapshot AND the snapshot was in a stable region
     *    (libart / boot OAT). Catches "was hooked since startup
     *    even if currently restored". JIT-cache snapshots are
     *    excluded from drift because legitimate JIT recompilation
     *    legitimately moves entries within / out of the cache.
     */
    private fun runVectorA(pkg: String): List<Finding> {
        val records = runCatching { NativeBridge.artIntegrityScan() }
            .onFailure { Log.w(TAG, "artIntegrityScan failed", it) }
            .getOrNull() ?: return emptyList()
        if (records.isEmpty()) {
            Log.w(TAG, "Vector A: scan returned no records (offset table missing?)")
            return emptyList()
        }
        // The native scan call ALSO recomputes the hash of the
        // self-protected baseline page; baselineIntact reflects
        // that check. If false, the page was tampered with
        // between scans — emit the dedicated finding here so
        // backends can pivot on the storage attack separately
        // from the entry-pointer attacks.
        val baselineIntact = runCatching { NativeBridge.artIntegrityBaselineIntact() }
            .getOrDefault(true)
        val findings = ArrayList<Finding>()
        if (!baselineIntact) {
            findings += Finding(
                kind = KIND_ART_BASELINE_TAMPERED,
                severity = Severity.HIGH,
                subject = pkg,
                message = "integrity.art baseline page hash mismatch — storage was tampered with between scans",
                details = mapOf("baseline_recaptured" to "true"),
            )
        }
        findings += vectorAFindingsFromRecords(records, pkg)
        val rangeCount = findings.count { it.kind == KIND_ART_METHOD_ENTRY_OUT_OF_RANGE }
        val driftCount = findings.count { it.kind == KIND_ART_METHOD_ENTRY_DRIFTED }
        val tamperCount = findings.count { it.kind == KIND_ART_BASELINE_TAMPERED }
        Log.i(
            TAG,
            "Vector A: scanned ${records.size} record(s), " +
                "out_of_range=$rangeCount drifted=$driftCount baseline_tampered=$tamperCount",
        )
        return findings
    }

    /**
     * Pure helper: parses the pipe-delimited records and emits
     * Vector A findings. Lives outside [runVectorA] so tests can
     * drive it without going through the JNI bridge.
     */
    internal fun vectorAFindingsFromRecords(records: Array<String>, pkg: String): List<Finding> {
        val findings = ArrayList<Finding>()
        for (rec in records) {
            val parsed = ScanRecord.parse(rec) ?: continue
            if (!parsed.readable) continue
            if (parsed.liveClass == "unknown") {
                findings += Finding(
                    kind = KIND_ART_METHOD_ENTRY_OUT_OF_RANGE,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod entry pointer points outside known ART memory regions",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                    ),
                )
            }
            if (parsed.drifted && shouldReportDrift(parsed)) {
                findings += Finding(
                    kind = KIND_ART_METHOD_ENTRY_DRIFTED,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod entry pointer changed since JNI_OnLoad snapshot",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                    ),
                )
            }
        }
        return findings
    }

    /**
     * Drift is reported when the snapshot→live region transition
     * cannot be explained by a benign ART-internal state change.
     *
     * Empirically-observed benign transitions on Android 13-16:
     *
     *  - **libart → libart**: ART installs lazy-resolution stubs
     *    (`art_quick_to_interpreter_bridge` and friends) at
     *    JNI_OnLoad; the first call resolves the method to its
     *    AOT body, which often lives in another part of libart's
     *    RX segment. The address differs but the classification
     *    is identical.
     *
     *  - **libart → boot_oat / libart → jit_cache**: same
     *    lazy-resolution pattern as above, but the resolved body
     *    lives in a boot OAT file or the JIT cache.
     *
     *  - **boot_oat → boot_oat**: similar boot-OAT-internal
     *    relinking happens for some methods.
     *
     *  - **jit_cache → jit_cache**: ART can re-JIT-compile a
     *    method at a higher tier (or after profile update), and
     *    the new entry usually lands elsewhere in the JIT cache.
     *    String.length is a stable example of this — its entry
     *    drifts within jit_cache on every cold start. We accept
     *    the trade-off that Frida-Java's `cls.method.implementation`
     *    on JIT-resident non-native methods (which also lands in
     *    jit_cache) is missed at this layer; Vectors E + F catch
     *    those cases via different fields.
     *
     *  - **snap == unknown**: the snapshot region wasn't one we
     *    classify (boot.art image stub, art-managed heap, etc).
     *    Without a stable baseline we can't reason about drift.
     *
     * Everything else is reported. Notably:
     *
     *  - `live == unknown` (snap in libart/boot_oat/jit_cache,
     *    live escapes all of them): canonical Frida / Xposed
     *    bridge in attacker-allocated memory.
     *  - `jit_cache → libart`: catches Frida-Java hooks on JDK
     *    native methods (Object#hashCode, Object#getClass) where
     *    the bridge lands on a libart-resident JNI dispatch stub.
     *  - `boot_oat → libart` / `jit_cache → boot_oat`: any other
     *    cross-region jump that isn't the lazy-resolution pattern.
     */
    private fun shouldReportDrift(record: ScanRecord): Boolean {
        val snap = record.snapshotClass
        val live = record.liveClass
        if (snap == "unknown") return false
        if (snap == "libart" && live == "libart") return false
        if (snap == "libart" && live == "boot_oat") return false
        if (snap == "libart" && live == "jit_cache") return false
        if (snap == "boot_oat" && live == "boot_oat") return false
        if (snap == "jit_cache" && live == "jit_cache") return false
        return true
    }

    /**
     * Vector C — re-reads the eight watched JNIEnv function-table
     * pointers, classifies each, and emits findings:
     *
     *  - `jni_env_table_out_of_range` (HIGH) — live pointer escapes
     *    libart's RX segment. Catches "currently hijacked".
     *  - `jni_env_table_drifted` (HIGH) — live differs from the
     *    JNI_OnLoad snapshot. Catches "was hijacked since startup".
     *    Unlike Vector A, there is no JIT-cache exception here:
     *    JNINativeInterface pointers do not legitimately move.
     *  - `jni_env_baseline_tampered` (HIGH) — the mmap-protected
     *    snapshot page itself was modified between scans.
     */
    private fun runVectorC(pkg: String): List<Finding> {
        val records = runCatching { NativeBridge.artIntegrityJniEnvScan() }
            .onFailure { Log.w(TAG, "artIntegrityJniEnvScan failed", it) }
            .getOrNull() ?: return emptyList()
        if (records.isEmpty()) {
            Log.w(TAG, "Vector C: scan returned no records (snapshot uninitialised?)")
            return emptyList()
        }
        val baselineIntact = runCatching { NativeBridge.artIntegrityJniEnvBaselineIntact() }
            .getOrDefault(true)
        val findings = ArrayList<Finding>()
        if (!baselineIntact) {
            findings += Finding(
                kind = KIND_JNI_ENV_BASELINE_TAMPERED,
                severity = Severity.HIGH,
                subject = pkg,
                message = "integrity.art JNIEnv baseline page hash mismatch — storage was tampered with between scans",
                details = mapOf("baseline_recaptured" to "true"),
            )
        }
        findings += vectorCFindingsFromRecords(records, pkg)
        val rangeCount = findings.count { it.kind == KIND_JNI_ENV_TABLE_OUT_OF_RANGE }
        val driftCount = findings.count { it.kind == KIND_JNI_ENV_TABLE_DRIFTED }
        val tamperCount = findings.count { it.kind == KIND_JNI_ENV_BASELINE_TAMPERED }
        Log.i(
            TAG,
            "Vector C: scanned ${records.size} record(s), " +
                "out_of_range=$rangeCount drifted=$driftCount baseline_tampered=$tamperCount",
        )
        return findings
    }

    /**
     * Pure helper: parses the pipe-delimited Vector C records and
     * emits findings. Lives outside [runVectorC] so unit tests can
     * exercise it without going through the JNI bridge.
     */
    internal fun vectorCFindingsFromRecords(records: Array<String>, pkg: String): List<Finding> {
        val findings = ArrayList<Finding>()
        for (rec in records) {
            val parsed = JniEnvScanRecord.parse(rec) ?: continue
            if (parsed.liveClass == "unknown") {
                findings += Finding(
                    kind = KIND_JNI_ENV_TABLE_OUT_OF_RANGE,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "JNIEnv function pointer points outside libart's RX segment",
                    details = mapOf(
                        "function" to parsed.functionName,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                    ),
                )
            }
            if (parsed.drifted) {
                findings += Finding(
                    kind = KIND_JNI_ENV_TABLE_DRIFTED,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "JNIEnv function pointer changed since JNI_OnLoad snapshot",
                    details = mapOf(
                        "function" to parsed.functionName,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                    ),
                )
            }
        }
        return findings
    }

    /**
     * Vector D — re-reads the first ~16 bytes of each tracked
     * libart hot-path symbol and emits findings:
     *
     *  - `art_internal_prologue_drifted` (HIGH) — live differs
     *    from the JNI_OnLoad snapshot. Catches Frida
     *    `Interceptor.attach` patches installed after our load.
     *  - `art_internal_prologue_baseline_mismatch` (MEDIUM) —
     *    live differs from the embedded per-API baseline. Could
     *    be a pre-load injector OR an unrecognised OEM ROM, so
     *    it's intentionally lower severity.
     *  - `art_internal_prologue_baseline_tampered` (HIGH) — the
     *    mmap-protected snapshot page itself was modified.
     */
    private fun runVectorD(pkg: String): List<Finding> {
        val records = runCatching { NativeBridge.artIntegrityInlinePrologueScan() }
            .onFailure { Log.w(TAG, "artIntegrityInlinePrologueScan failed", it) }
            .getOrNull() ?: return emptyList()
        if (records.isEmpty()) {
            Log.w(TAG, "Vector D: scan returned no records (libart symbols missing?)")
            return emptyList()
        }
        val baselineIntact = runCatching {
            NativeBridge.artIntegrityInlinePrologueBaselineIntact()
        }.getOrDefault(true)
        val findings = ArrayList<Finding>()
        if (!baselineIntact) {
            findings += Finding(
                kind = KIND_ART_INTERNAL_PROLOGUE_BASELINE_TAMPERED,
                severity = Severity.HIGH,
                subject = pkg,
                message = "integrity.art inline-prologue baseline page hash mismatch — storage was tampered with between scans",
                details = mapOf("baseline_recaptured" to "true"),
            )
        }
        findings += vectorDFindingsFromRecords(records, pkg)
        val driftCount = findings.count { it.kind == KIND_ART_INTERNAL_PROLOGUE_DRIFTED }
        val baselineMismatchCount =
            findings.count { it.kind == KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH }
        val tamperCount =
            findings.count { it.kind == KIND_ART_INTERNAL_PROLOGUE_BASELINE_TAMPERED }
        Log.i(
            TAG,
            "Vector D: scanned ${records.size} record(s), " +
                "drifted=$driftCount baseline_mismatch=$baselineMismatchCount " +
                "baseline_tampered=$tamperCount",
        )
        return findings
    }

    /**
     * Pure helper: parses the pipe-delimited Vector D records
     * and emits findings. Lives outside [runVectorD] so unit
     * tests can exercise it without going through the JNI bridge.
     */
    internal fun vectorDFindingsFromRecords(records: Array<String>, pkg: String): List<Finding> {
        val findings = ArrayList<Finding>()
        for (rec in records) {
            val parsed = InlinePrologueScanRecord.parse(rec) ?: continue
            if (!parsed.resolved) continue
            if (parsed.drifted) {
                findings += Finding(
                    kind = KIND_ART_INTERNAL_PROLOGUE_DRIFTED,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ART internal function prologue changed since JNI_OnLoad snapshot",
                    details = mapOf(
                        "symbol" to parsed.symbol,
                        "address" to parsed.addressHex,
                        "live_bytes" to parsed.liveHex,
                        "snapshot_bytes" to parsed.snapshotHex,
                    ),
                )
            }
            if (parsed.baselineKnown && parsed.baselineMismatch) {
                findings += Finding(
                    kind = KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH,
                    severity = Severity.MEDIUM,
                    subject = pkg,
                    message = "ART internal function prologue differs from embedded per-API baseline",
                    details = mapOf(
                        "symbol" to parsed.symbol,
                        "address" to parsed.addressHex,
                        "live_bytes" to parsed.liveHex,
                    ),
                )
            }
        }
        return findings
    }

    /**
     * Vector E — re-reads `entry_point_from_jni_` for each
     * registry slot and emits findings:
     *
     *  - `art_method_jni_entry_drifted` (HIGH) — live differs
     *    from snapshot on a method that was native at JNI_OnLoad.
     *    Catches the canonical Frida-Java native-method bridge
     *    install. We restrict drift reporting to native methods
     *    because for non-native methods the same slot is `data_`
     *    (ProfilingInfo / hotness counter), whose value
     *    legitimately changes during JIT activity.
     *  - `art_method_jni_entry_out_of_range` (HIGH) — live
     *    pointer escapes libart / boot OAT / JIT cache regardless
     *    of the method's native bit. Catches Frida-Java attaching
     *    to a non-native method too: the bridge pointer ends up
     *    in attacker-allocated memory, which classifies as
     *    "unknown".
     *  - `art_method_jni_entry_baseline_tampered` (HIGH) — the
     *    mmap-protected snapshot page itself was modified.
     */
    private fun runVectorE(pkg: String): List<Finding> {
        val records = runCatching { NativeBridge.artIntegrityJniEntryScan() }
            .onFailure { Log.w(TAG, "artIntegrityJniEntryScan failed", it) }
            .getOrNull() ?: return emptyList()
        if (records.isEmpty()) {
            Log.w(TAG, "Vector E: scan returned no records (snapshot uninitialised?)")
            return emptyList()
        }
        val baselineIntact = runCatching { NativeBridge.artIntegrityJniEntryBaselineIntact() }
            .getOrDefault(true)
        val findings = ArrayList<Finding>()
        if (!baselineIntact) {
            findings += Finding(
                kind = KIND_ART_METHOD_JNI_ENTRY_BASELINE_TAMPERED,
                severity = Severity.HIGH,
                subject = pkg,
                message = "integrity.art JNI-entry baseline page hash mismatch — storage was tampered with between scans",
                details = mapOf("baseline_recaptured" to "true"),
            )
        }
        findings += vectorEFindingsFromRecords(records, pkg)
        val rangeCount = findings.count { it.kind == KIND_ART_METHOD_JNI_ENTRY_OUT_OF_RANGE }
        val driftCount = findings.count { it.kind == KIND_ART_METHOD_JNI_ENTRY_DRIFTED }
        val tamperCount = findings.count { it.kind == KIND_ART_METHOD_JNI_ENTRY_BASELINE_TAMPERED }
        Log.i(
            TAG,
            "Vector E: scanned ${records.size} record(s), " +
                "out_of_range=$rangeCount drifted=$driftCount baseline_tampered=$tamperCount",
        )
        return findings
    }

    /**
     * Pure helper: parses the pipe-delimited Vector E records
     * and emits findings.
     *
     * **Out-of-range is gated on a known→unknown transition**
     * (snap_class in {libart, boot_oat}, live_class == unknown).
     * For many native methods the `data_` slot is initialized to
     * point inside the boot image (`boot.art`), which our
     * classifier doesn't recognise and so already reads as
     * `unknown` at snapshot time. Without this gate, every
     * boot-image-resolved native method would false-positive on
     * a clean device. The drift signal below still catches the
     * Frida-Java case where the boot-image stub gets overwritten
     * with a bridge pointer (different value, same `unknown`
     * classification).
     *
     * **Drift is gated on `isNativeBySpec=1`** (i.e. the registry's
     * static `MethodKind == JNI_NATIVE`), not on the runtime
     * ACC_NATIVE bit. ART intrinsifies several declared-native
     * methods (Object#hashCode, Object#getClass, …) and clears
     * the runtime ACC_NATIVE bit on them — but their `data_`
     * slot still holds the JNI bridge, so an attacker overwrite
     * is real signal even when the runtime bit reads 0. For
     * non-native methods (kind != JNI_NATIVE) the same slot is
     * `data_` (ProfilingInfo / hotness counter), whose value
     * legitimately changes during JIT activity, so we suppress
     * drift there.
     *
     * **Drift is also gated on a non-benign transition**
     * (`shouldReportJniEntryDrift`). HwART (and AOSP under some
     * conditions) re-links a declared-native method's `data_`
     * slot during normal execution: the JNI_OnLoad snapshot may
     * capture a lazy-resolution stub, and the first call resolves
     * it to the actual JNI bridge — the address differs but both
     * sit in legitimate ART memory. Empirically observed on
     * Huawei API 31; suppressed here so a clean device stays
     * silent.
     */
    internal fun vectorEFindingsFromRecords(records: Array<String>, pkg: String): List<Finding> {
        val findings = ArrayList<Finding>()
        for (rec in records) {
            val parsed = JniEntryScanRecord.parse(rec) ?: continue
            if (!parsed.readable) continue
            val snapWasKnown =
                parsed.snapshotClass == "libart" || parsed.snapshotClass == "boot_oat"
            if (snapWasKnown && parsed.liveClass == "unknown") {
                findings += Finding(
                    kind = KIND_ART_METHOD_JNI_ENTRY_OUT_OF_RANGE,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod entry_point_from_jni_ now points outside known ART memory regions",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                        "is_native_by_spec" to parsed.isNativeBySpec.toString(),
                    ),
                )
            }
            if (parsed.drifted && parsed.isNativeBySpec && shouldReportJniEntryDrift(parsed)) {
                findings += Finding(
                    kind = KIND_ART_METHOD_JNI_ENTRY_DRIFTED,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod entry_point_from_jni_ changed since JNI_OnLoad snapshot",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "live_address" to parsed.liveHex,
                        "snapshot_address" to parsed.snapshotHex,
                        "live_classification" to parsed.liveClass,
                        "snapshot_classification" to parsed.snapshotClass,
                    ),
                )
            }
        }
        return findings
    }

    /**
     * Vector E drift is reported when the snapshot→live transition
     * cannot be explained by benign ART-internal re-linking of a
     * declared-native method's `data_` slot.
     *
     * Benign known→known transitions on devices we've tested:
     *
     *  - **libart → libart**: ART can re-resolve a JNI bridge
     *    within libart's RX segment. Empirically observed on
     *    Huawei API 31 for `Object#hashCode` and friends, where
     *    the snapshot captured a `art_jni_dlsym_lookup_*` stub
     *    and the first call replaced it with the actual bridge.
     *
     *  - **libart → boot_oat / boot_oat → libart**: cross-region
     *    resolution between the boot image and libart. Less
     *    common but observed on some HwART / Samsung builds.
     *
     *  - **boot_oat → boot_oat**: rare bridge movement within
     *    boot images; treat as benign.
     *
     * Transitions that **always** report:
     *
     *  - **anything → unknown**: covered by the dedicated
     *    out_of_range path above; drift fires too because the
     *    value also changed (and a backend may want both).
     *
     *  - **unknown → anything**: an unknown snapshot covers
     *    boot.art-resident stubs the classifier doesn't
     *    recognise. A value change there is the canonical
     *    Frida-Java attack on declared-native methods (e.g.
     *    bridge overwrite of `Object.hashCode`'s `data_`); we
     *    can't distinguish "stub resolved into bridge" from
     *    "attacker bridge install" without more context, so we
     *    report and let the backend pivot on
     *    `live_classification`.
     *
     *  - **libart → jit_cache / boot_oat → jit_cache /
     *    jit_cache → anything**: declared-native methods do
     *    not legitimately route through the JIT cache for
     *    their `data_` slot. Anything involving JIT here is
     *    surprising and worth surfacing.
     */
    private fun shouldReportJniEntryDrift(record: JniEntryScanRecord): Boolean {
        val snap = record.snapshotClass
        val live = record.liveClass
        if (snap == "libart" && live == "libart") return false
        if (snap == "libart" && live == "boot_oat") return false
        if (snap == "boot_oat" && live == "libart") return false
        if (snap == "boot_oat" && live == "boot_oat") return false
        return true
    }

    /**
     * Vector F — re-reads `access_flags_` for each registry slot
     * and emits findings only on bit-flips:
     *
     *  - `art_method_acc_native_flipped_on` (HIGH) — the
     *    `ACC_NATIVE` bit went 0 → 1. Java methods do not become
     *    native at runtime; this is a binary, unambiguous
     *    Frida-Java fingerprint.
     *  - `art_method_acc_native_flipped_off` (HIGH) — the
     *    `ACC_NATIVE` bit went 1 → 0 on a method that was native
     *    at startup. Rare, but no legitimate runtime path clears
     *    this bit either.
     *  - `art_method_access_flags_baseline_tampered` (HIGH) — the
     *    mmap-protected snapshot page itself was modified.
     *
     * The broader `any_drift` signal (other access_flags_ bits
     * differ) is logged but not surfaced as a finding — ART
     * itself flips intrinsic / hotness markers in this same
     * field during normal execution.
     */
    private fun runVectorF(pkg: String): List<Finding> {
        val records = runCatching { NativeBridge.artIntegrityAccessFlagsScan() }
            .onFailure { Log.w(TAG, "artIntegrityAccessFlagsScan failed", it) }
            .getOrNull() ?: return emptyList()
        if (records.isEmpty()) {
            Log.w(TAG, "Vector F: scan returned no records (snapshot uninitialised?)")
            return emptyList()
        }
        val baselineIntact = runCatching { NativeBridge.artIntegrityAccessFlagsBaselineIntact() }
            .getOrDefault(true)
        val findings = ArrayList<Finding>()
        if (!baselineIntact) {
            findings += Finding(
                kind = KIND_ART_METHOD_ACCESS_FLAGS_BASELINE_TAMPERED,
                severity = Severity.HIGH,
                subject = pkg,
                message = "integrity.art access-flags baseline page hash mismatch — storage was tampered with between scans",
                details = mapOf("baseline_recaptured" to "true"),
            )
        }
        findings += vectorFFindingsFromRecords(records, pkg)
        val flipOnCount = findings.count { it.kind == KIND_ART_METHOD_ACC_NATIVE_FLIPPED_ON }
        val flipOffCount = findings.count { it.kind == KIND_ART_METHOD_ACC_NATIVE_FLIPPED_OFF }
        val tamperCount = findings.count { it.kind == KIND_ART_METHOD_ACCESS_FLAGS_BASELINE_TAMPERED }
        Log.i(
            TAG,
            "Vector F: scanned ${records.size} record(s), " +
                "flipped_on=$flipOnCount flipped_off=$flipOffCount baseline_tampered=$tamperCount",
        )
        return findings
    }

    /**
     * Pure helper: parses the pipe-delimited Vector F records
     * and emits ACC_NATIVE flip findings.
     */
    internal fun vectorFFindingsFromRecords(records: Array<String>, pkg: String): List<Finding> {
        val findings = ArrayList<Finding>()
        for (rec in records) {
            val parsed = AccessFlagsScanRecord.parse(rec) ?: continue
            if (!parsed.readable) continue
            if (parsed.nativeFlippedOn) {
                findings += Finding(
                    kind = KIND_ART_METHOD_ACC_NATIVE_FLIPPED_ON,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod ACC_NATIVE bit flipped ON since JNI_OnLoad — Java method now dispatches as native (canonical Frida-Java fingerprint)",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "snapshot_flags" to parsed.snapshotFlagsHex,
                        "live_flags" to parsed.liveFlagsHex,
                    ),
                )
            }
            if (parsed.nativeFlippedOff) {
                findings += Finding(
                    kind = KIND_ART_METHOD_ACC_NATIVE_FLIPPED_OFF,
                    severity = Severity.HIGH,
                    subject = pkg,
                    message = "ArtMethod ACC_NATIVE bit flipped OFF since JNI_OnLoad — native method de-flagged at runtime",
                    details = mapOf(
                        "method" to parsed.shortId,
                        "snapshot_flags" to parsed.snapshotFlagsHex,
                        "live_flags" to parsed.liveFlagsHex,
                    ),
                )
            }
        }
        return findings
    }

    /**
     * Pipe-delimited record returned by `NativeBridge.artIntegrityScan()`:
     * `short_id|live_hex|snap_hex|live_class|snap_class|readable|drifted`
     */
    internal data class ScanRecord(
        val shortId: String,
        val liveHex: String,
        val snapshotHex: String,
        val liveClass: String,
        val snapshotClass: String,
        val readable: Boolean,
        val drifted: Boolean,
    ) {
        companion object {
            fun parse(record: String): ScanRecord? {
                val parts = record.split('|')
                if (parts.size < 7) return null
                return ScanRecord(
                    shortId = parts[0],
                    liveHex = parts[1],
                    snapshotHex = parts[2],
                    liveClass = parts[3],
                    snapshotClass = parts[4],
                    readable = parts[5] == "1",
                    drifted = parts[6] == "1",
                )
            }
        }
    }

    /**
     * Pipe-delimited record returned by `NativeBridge.artIntegrityJniEnvScan()`:
     * `function_name|live_hex|snap_hex|live_class|snap_class|drifted`
     *
     * Note the absence of a `readable` flag — JNINativeInterface
     * pointers are always direct function addresses (no INDEX
     * encoding), so every record is meaningful.
     */
    internal data class JniEnvScanRecord(
        val functionName: String,
        val liveHex: String,
        val snapshotHex: String,
        val liveClass: String,
        val snapshotClass: String,
        val drifted: Boolean,
    ) {
        companion object {
            fun parse(record: String): JniEnvScanRecord? {
                val parts = record.split('|')
                if (parts.size < 6) return null
                return JniEnvScanRecord(
                    functionName = parts[0],
                    liveHex = parts[1],
                    snapshotHex = parts[2],
                    liveClass = parts[3],
                    snapshotClass = parts[4],
                    drifted = parts[5] == "1",
                )
            }
        }
    }

    /**
     * Pipe-delimited record returned by
     * `NativeBridge.artIntegrityInlinePrologueScan()`:
     * `symbol|addr_hex|live_hex|snap_hex|resolved|drifted|baseline_known|baseline_mismatch`
     */
    internal data class InlinePrologueScanRecord(
        val symbol: String,
        val addressHex: String,
        val liveHex: String,
        val snapshotHex: String,
        val resolved: Boolean,
        val drifted: Boolean,
        val baselineKnown: Boolean,
        val baselineMismatch: Boolean,
    ) {
        companion object {
            fun parse(record: String): InlinePrologueScanRecord? {
                val parts = record.split('|')
                if (parts.size < 8) return null
                return InlinePrologueScanRecord(
                    symbol = parts[0],
                    addressHex = parts[1],
                    liveHex = parts[2],
                    snapshotHex = parts[3],
                    resolved = parts[4] == "1",
                    drifted = parts[5] == "1",
                    baselineKnown = parts[6] == "1",
                    baselineMismatch = parts[7] == "1",
                )
            }
        }
    }

    /**
     * Pipe-delimited record returned by
     * `NativeBridge.artIntegrityJniEntryScan()`:
     * `short_id|live_hex|snap_hex|live_class|snap_class|readable|drifted|is_native_by_spec`
     *
     * `isNativeBySpec` reflects the JDK declaration (registry's
     * `MethodKind == JNI_NATIVE`), not the runtime ACC_NATIVE
     * bit, because ART intrinsifies several declared-native
     * methods (Object#hashCode, Object#getClass) and clears the
     * runtime bit on them — but their `data_` slot still holds
     * the JNI bridge pointer, so attacker drift there is real
     * signal. See [vectorEFindingsFromRecords] for the rationale.
     */
    internal data class JniEntryScanRecord(
        val shortId: String,
        val liveHex: String,
        val snapshotHex: String,
        val liveClass: String,
        val snapshotClass: String,
        val readable: Boolean,
        val drifted: Boolean,
        val isNativeBySpec: Boolean,
    ) {
        companion object {
            fun parse(record: String): JniEntryScanRecord? {
                val parts = record.split('|')
                if (parts.size < 8) return null
                return JniEntryScanRecord(
                    shortId = parts[0],
                    liveHex = parts[1],
                    snapshotHex = parts[2],
                    liveClass = parts[3],
                    snapshotClass = parts[4],
                    readable = parts[5] == "1",
                    drifted = parts[6] == "1",
                    isNativeBySpec = parts[7] == "1",
                )
            }
        }
    }

    /**
     * Pipe-delimited record returned by
     * `NativeBridge.artIntegrityAccessFlagsScan()`:
     * `short_id|live_flags_hex|snap_flags_hex|readable|flip_on|flip_off|any_drift`
     */
    internal data class AccessFlagsScanRecord(
        val shortId: String,
        val liveFlagsHex: String,
        val snapshotFlagsHex: String,
        val readable: Boolean,
        val nativeFlippedOn: Boolean,
        val nativeFlippedOff: Boolean,
        val anyDrift: Boolean,
    ) {
        companion object {
            fun parse(record: String): AccessFlagsScanRecord? {
                val parts = record.split('|')
                if (parts.size < 7) return null
                return AccessFlagsScanRecord(
                    shortId = parts[0],
                    liveFlagsHex = parts[1],
                    snapshotFlagsHex = parts[2],
                    readable = parts[3] == "1",
                    nativeFlippedOn = parts[4] == "1",
                    nativeFlippedOff = parts[5] == "1",
                    anyDrift = parts[6] == "1",
                )
            }
        }
    }

    /**
     * Test-only no-op kept for backwards compatibility with the
     * red-team Frida scripts that called this to drop the
     * (now-removed) verdict cache. integrity.art no longer caches verdicts
     * across calls, so this is a no-op; the next [evaluate] will
     * re-scan regardless of whether this is called.
     */
    fun resetForTest() {
        // intentionally empty: no per-process verdict cache to drop
    }
}
