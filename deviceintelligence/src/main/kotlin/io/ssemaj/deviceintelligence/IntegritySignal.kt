package io.ssemaj.deviceintelligence

/**
 * Coarse, backend-friendly classification of what a [TelemetryReport]
 * actually *means*.
 *
 * [TelemetryReport] is intentionally low-level: every detector reports
 * its individual [Finding]s with stable per-kind identifiers
 * (`apk_signer_mismatch`, `art_method_entry_drifted`,
 * `injected_anonymous_executable`, …). That granularity is the right
 * thing to ship to a backend — it preserves forensic evidence and
 * lets a SOC team pivot on individual signals — but it is the wrong
 * thing to put in front of a product code path that only needs to
 * know "should I trust this session?".
 *
 * [IntegritySignal] folds the ~40 per-kind identifiers into 11
 * orthogonal high-level buckets. Consumers who only need a verdict
 * (UI gating, telemetry counters, support-tooling banners) can pivot
 * on this set directly; consumers who need the underlying evidence
 * still have the original [Finding]s available via
 * [IntegritySignalReport.evidence].
 *
 * The mapping is **deliberately conservative**: a single finding
 * always maps to exactly one signal; any unrecognised finding kind
 * (e.g. a kind added in a newer library version that this consumer
 * hasn't been recompiled against) is surfaced via
 * [IntegritySignalReport.unmappedFindings] rather than silently
 * dropped.
 *
 * @see IntegritySignalMapper
 * @see TelemetryReport.toIntegritySignals
 */
public enum class IntegritySignal {

    // ---- APK / package surface ------------------------------------------

    /**
     * The APK on disk has been modified or repackaged: signer cert
     * doesn't match the build-time baseline, an entry was added /
     * removed / mutated, the install path is suspicious, or the
     * installer package is outside the configured allowlist.
     *
     * Backed by `integrity.apk` finding kinds:
     * `apk_signer_mismatch`, `apk_source_dir_unexpected`,
     * `installer_not_whitelisted`, `apk_entry_added`,
     * `apk_entry_removed`, `apk_entry_modified`.
     */
    APK_TAMPERED,

    /**
     * The build-time fingerprint asset that `integrity.apk` would
     * verify against is missing or corrupt — the APK was repackaged
     * with codegen stripped, the asset was deleted, or the blob
     * format was tampered with. The detector cannot make a verdict
     * either way; treat as a strong "couldn't verify" signal.
     *
     * Backed by `integrity.apk` finding kinds:
     * `fingerprint_asset_missing`, `fingerprint_key_missing`,
     * `fingerprint_bad_magic`, `fingerprint_corrupt`.
     */
    APK_FINGERPRINT_UNAVAILABLE,

    // ---- Bootloader / TEE -----------------------------------------------

    /**
     * The hardware key-attestation chain has structural / freshness /
     * consistency anomalies, OR the device advertises StrongBox but
     * attests at a lower security level. Either way: the bootloader
     * /TEE surface is in a state that warrants backend re-verification
     * of the raw chain (see [AppContext.attestation]).
     *
     * Backed by `integrity.bootloader` finding kinds:
     * `bootloader_integrity_anomaly`, `bootloader_strongbox_unavailable`.
     */
    BOOTLOADER_INTEGRITY_FAILED,

    /**
     * The locally derived advisory verdict from `attestation.key`
     * came back degraded (less than `MEETS_STRONG_INTEGRITY`, or with
     * a [AttestationReport.verdictReason] populated). Always
     * advisory; backends should treat the raw chain as the
     * authoritative source of truth.
     *
     * Backed by `attestation.key` finding kind: `tee_integrity_verdict`.
     */
    TEE_ATTESTATION_DEGRADED,

    // ---- Active hooking / runtime tampering -----------------------------

    /**
     * Active code-level hooking detected somewhere in the process.
     * Catches every vector the library probes for:
     *
     *  - Java/Kotlin method hooks visible on the call stack
     *    (LSPosed, Xposed, YAHFA, SandHook, Pine, Substrate, Frida
     *    Java hooks).
     *  - ART-internals tampering (entry-point rewrites, JNIEnv
     *    table hijacks, ACC_NATIVE flips, internal-prologue
     *    rewrites).
     *  - libdicore.so own-code tampering (.text hash mismatch /
     *    drift, GOT/GOT.PLT entry rewrites, JNI return-address
     *    landing in a foreign region).
     *  - Process-wide anomaly fingerprints (RWX trampoline pages,
     *    known hook-framework library names visible in the loader
     *    list).
     *
     * Backed by `runtime.environment` and `integrity.art` finding
     * kinds: `hook_framework_present`, `rwx_memory_mapping`,
     * `stack_foreign_frame`, `native_caller_out_of_range`,
     * `native_text_hash_mismatch`, `native_text_drifted`,
     * `got_entry_drifted`, `got_entry_out_of_range`, all `art_*` and
     * `jni_env_*` kinds.
     */
    HOOKING_FRAMEWORK_DETECTED,

    /**
     * A loaded shared library or anonymous executable mapping
     * appeared post-baseline that does not belong to any system /
     * app-private path the library trusts. Distinct from
     * [HOOKING_FRAMEWORK_DETECTED] because the *presence* of unknown
     * native code does not, on its own, prove that any hooking has
     * happened — but it is a near-universal precondition for it
     * (Frida agents, Zygisk modules, generic shellcode loaders).
     *
     * Backed by `runtime.environment` finding kinds:
     * `injected_library`, `injected_anonymous_executable`.
     */
    INJECTED_NATIVE_CODE,

    // ---- Privilege / environment ----------------------------------------

    /**
     * One or more root indicators are present on the device:
     * `su` binary on the path, Magisk artifact, `test-keys` build,
     * `which su` returns success, or a known root-manager app
     * package is installed.
     *
     * Backed by `runtime.root` finding kinds:
     * `su_binary_present`, `magisk_artifact_present`,
     * `test_keys_build`, `which_su_succeeded`,
     * `root_manager_app_installed`.
     */
    ROOT_INDICATORS_PRESENT,

    /**
     * The process is running on an emulator or virtualised device
     * (CPU-instruction-level signals: arm64 MRS or x86_64 CPUID
     * hypervisor bit).
     *
     * Backed by `runtime.emulator` finding kind: `running_on_emulator`.
     */
    EMULATOR_DETECTED,

    /**
     * The process is running inside an app cloner / parallel-space
     * container: foreign APK mappings in our address space, mount
     * namespace inconsistencies, or a UID disagreement between the
     * Java view and the kernel view.
     *
     * Backed by `runtime.cloner` finding kinds:
     * `apk_path_mismatch`, `data_dir_mount_invalid`, `uid_mismatch`.
     */
    APP_CLONED,

    // ---- Debugger -------------------------------------------------------

    /**
     * A JVM debugger is currently attached, OR the kernel reports a
     * non-zero `TracerPid` for our process (ptrace attached). The
     * library only fires this when the consumer's app has been
     * built non-debuggable; debuggable builds suppress it.
     *
     * Backed by `runtime.environment` finding kind: `debugger_attached`.
     */
    DEBUGGER_ATTACHED,

    /**
     * The process's `ApplicationInfo.FLAG_DEBUGGABLE` disagrees with
     * the system property `ro.debuggable`. Either the app is shipped
     * as a release build but a userdebug ROM is exposing it as
     * debuggable, or the app is debuggable on a "production" ROM —
     * both cases are interesting to a backend that wants to cohort
     * "debuggable-on-prod-ROM" sessions out of analytics.
     *
     * Backed by `runtime.environment` finding kind:
     * `ro_debuggable_mismatch`.
     */
    DEBUG_FLAG_MISMATCH,
}

/**
 * Result of mapping a [TelemetryReport]'s low-level findings into
 * the high-level [IntegritySignal] vocabulary.
 *
 * Three views over the same underlying data:
 *
 *  - [signals] — the deduplicated set of high-level signals raised.
 *    Drop-in for `if (HOOKING_FRAMEWORK_DETECTED in signals)` checks.
 *  - [evidence] — for each raised signal, the exact list of
 *    [Finding]s that caused it. Use when you need to render the
 *    detailed reason (e.g. show "LSPosed bridge frame on stack" in
 *    a support panel).
 *  - [unmappedFindings] — findings whose [Finding.kind] this version
 *    of the library did not recognise. Surfaced rather than silently
 *    dropped so that a consumer compiled against an older mapper
 *    still notices when the runtime is producing new finding kinds.
 *    A non-empty list here is your cue to bump the SDK version.
 */
public data class IntegritySignalReport(
    public val signals: Set<IntegritySignal>,
    public val evidence: Map<IntegritySignal, List<Finding>>,
    public val unmappedFindings: List<Finding>,
) {
    public companion object {
        /** Empty report — no findings, no signals. */
        @JvmField
        public val EMPTY: IntegritySignalReport = IntegritySignalReport(
            signals = emptySet(),
            evidence = emptyMap(),
            unmappedFindings = emptyList(),
        )
    }
}

/**
 * Folds the granular per-detector [Finding] vocabulary down into the
 * high-level [IntegritySignal] vocabulary.
 *
 * The mapper is **stateless and pure** — call it from any thread,
 * cache the result yourself if you care. It does NOT inspect
 * [DetectorReport.status] (so a report whose detector errored is
 * still safely mappable; only the [Finding]s it managed to produce
 * are lifted), it does NOT consider [Finding.severity] (severity is
 * advisory; the mapping is purely on stable [Finding.kind]), and it
 * does NOT deduplicate the underlying findings (a single
 * [IntegritySignal] may be evidenced by many findings).
 *
 * Backends that prefer to do this lifting server-side can replicate
 * the mapping table — every entry below pivots only on
 * [Finding.kind], which is a stable wire-format identifier per
 * [TELEMETRY_SCHEMA_VERSION].
 *
 * @see IntegritySignal for the full vocabulary
 * @see IntegritySignalReport for the return shape
 */
public object IntegritySignalMapper {

    /**
     * Returns just the deduplicated set of high-level signals. Use
     * when the caller only needs membership checks and not the
     * underlying evidence. Equivalent to
     * `report(input).signals` but skips the evidence map allocation.
     */
    @JvmStatic
    public fun signalsOf(input: TelemetryReport): Set<IntegritySignal> {
        if (input.detectors.isEmpty()) return emptySet()
        val out = HashSet<IntegritySignal>(KIND_TO_SIGNAL.values.distinct().size.coerceAtLeast(4))
        for (detector in input.detectors) {
            for (finding in detector.findings) {
                val signal = KIND_TO_SIGNAL[finding.kind] ?: continue
                out += signal
            }
        }
        return out
    }

    /**
     * Returns the full mapping result: signals, per-signal evidence,
     * and any findings whose kind this mapper version doesn't
     * recognise. Use when the caller needs to render or attribute
     * the underlying [Finding]s.
     */
    @JvmStatic
    public fun report(input: TelemetryReport): IntegritySignalReport {
        if (input.detectors.isEmpty()) return IntegritySignalReport.EMPTY
        val evidence = LinkedHashMap<IntegritySignal, MutableList<Finding>>()
        val unmapped = ArrayList<Finding>()
        for (detector in input.detectors) {
            for (finding in detector.findings) {
                val signal = KIND_TO_SIGNAL[finding.kind]
                if (signal == null) {
                    unmapped += finding
                } else {
                    evidence.getOrPut(signal) { ArrayList(2) } += finding
                }
            }
        }
        if (evidence.isEmpty() && unmapped.isEmpty()) return IntegritySignalReport.EMPTY
        return IntegritySignalReport(
            signals = evidence.keys.toSet(),
            evidence = evidence.mapValues { (_, v) -> v.toList() },
            unmappedFindings = unmapped.toList(),
        )
    }

    /**
     * The full mapping table from stable [Finding.kind] strings to
     * [IntegritySignal] buckets. Exposed (read-only) so backends and
     * tests can introspect the vocabulary; mutating callers should
     * make a copy. Adding a new finding kind to the library means
     * adding an entry here in the same change.
     */
    @JvmStatic
    public val kindToSignal: Map<String, IntegritySignal>
        get() = KIND_TO_SIGNAL
}

/**
 * Convenience extension for the common "just give me the high-level
 * signals" case. Equivalent to [IntegritySignalMapper.signalsOf].
 */
public fun TelemetryReport.toIntegritySignals(): Set<IntegritySignal> =
    IntegritySignalMapper.signalsOf(this)

/**
 * Convenience extension for the "give me the signals plus the
 * underlying evidence" case. Equivalent to
 * [IntegritySignalMapper.report].
 */
public fun TelemetryReport.toIntegritySignalReport(): IntegritySignalReport =
    IntegritySignalMapper.report(this)

/**
 * Single source of truth for the kind → signal mapping. Kept
 * private to the file so callers can't accidentally mutate it.
 *
 * String literals (rather than references to the detectors' own
 * `KIND_*` constants) are deliberate: those constants are
 * `internal` to keep the per-detector implementation surface small,
 * and copying the strings here means the public mapper stays
 * decoupled from the detector internals. The trade-off is that
 * adding a new finding kind requires editing TWO places (the
 * detector AND this map) — that's intentional friction; it forces a
 * conscious choice about how the new kind should bucket up.
 *
 * Detector source-of-truth references (grep these to verify):
 *  - `integrity.apk`         → ApkIntegrityDetector
 *  - `integrity.bootloader`  → BootloaderIntegrityDetector
 *  - `integrity.art`         → ArtIntegrityDetector
 *  - `attestation.key`       → KeyAttestationDetector
 *  - `runtime.environment`   → RuntimeEnvironmentDetector + NativeIntegrityFindings
 *  - `runtime.root`          → RootIndicatorsDetector
 *  - `runtime.emulator`      → EmulatorProbe
 *  - `runtime.cloner`        → ClonerDetector
 */
private val KIND_TO_SIGNAL: Map<String, IntegritySignal> = buildMap {
    // ---- integrity.apk ----
    put("apk_signer_mismatch", IntegritySignal.APK_TAMPERED)
    put("apk_source_dir_unexpected", IntegritySignal.APK_TAMPERED)
    put("installer_not_whitelisted", IntegritySignal.APK_TAMPERED)
    put("apk_entry_removed", IntegritySignal.APK_TAMPERED)
    put("apk_entry_modified", IntegritySignal.APK_TAMPERED)
    put("apk_entry_added", IntegritySignal.APK_TAMPERED)
    put("fingerprint_asset_missing", IntegritySignal.APK_FINGERPRINT_UNAVAILABLE)
    put("fingerprint_key_missing", IntegritySignal.APK_FINGERPRINT_UNAVAILABLE)
    put("fingerprint_bad_magic", IntegritySignal.APK_FINGERPRINT_UNAVAILABLE)
    put("fingerprint_corrupt", IntegritySignal.APK_FINGERPRINT_UNAVAILABLE)

    // ---- integrity.bootloader ----
    put("bootloader_integrity_anomaly", IntegritySignal.BOOTLOADER_INTEGRITY_FAILED)
    put("bootloader_strongbox_unavailable", IntegritySignal.BOOTLOADER_INTEGRITY_FAILED)

    // ---- attestation.key ----
    put("tee_integrity_verdict", IntegritySignal.TEE_ATTESTATION_DEGRADED)

    // ---- integrity.art (ART/JNI hooking surface) ----
    put("art_method_entry_out_of_range", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_entry_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_baseline_tampered", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("jni_env_table_out_of_range", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("jni_env_table_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("jni_env_baseline_tampered", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_internal_prologue_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_internal_prologue_baseline_mismatch", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_internal_prologue_baseline_tampered", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_jni_entry_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_jni_entry_out_of_range", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_jni_entry_baseline_tampered", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_acc_native_flipped_on", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_acc_native_flipped_off", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("art_method_access_flags_baseline_tampered", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)

    // ---- runtime.environment hookers + native integrity (G2/G4/G5/G6/G7) ----
    put("hook_framework_present", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("rwx_memory_mapping", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("stack_foreign_frame", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("native_caller_out_of_range", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("native_text_hash_mismatch", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("native_text_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("got_entry_drifted", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)
    put("got_entry_out_of_range", IntegritySignal.HOOKING_FRAMEWORK_DETECTED)

    // ---- runtime.environment injected native code (G3) ----
    put("injected_library", IntegritySignal.INJECTED_NATIVE_CODE)
    put("injected_anonymous_executable", IntegritySignal.INJECTED_NATIVE_CODE)
    // `system_library_late_loaded` is intentionally NOT mapped here.
    // It's a MEDIUM-severity, forensics-only finding emitted when a
    // library missed the JNI_OnLoad baseline but lives under a
    // dm-verity-protected AOSP system path (e.g. `/vendor/lib64/`
    // GL drivers lazy-loaded by the emulator). Surfacing it as
    // [INJECTED_NATIVE_CODE] would trip the high-level signal on
    // every clean emulator, defeating the whole point of the soft
    // classification. If a real attacker is ever found writing into
    // a system partition, that's caught by `runtime.root` /
    // `integrity.bootloader` / `attestation.key`, not here.

    // ---- runtime.environment debugger surface ----
    put("debugger_attached", IntegritySignal.DEBUGGER_ATTACHED)
    put("ro_debuggable_mismatch", IntegritySignal.DEBUG_FLAG_MISMATCH)

    // ---- runtime.root ----
    put("su_binary_present", IntegritySignal.ROOT_INDICATORS_PRESENT)
    put("magisk_artifact_present", IntegritySignal.ROOT_INDICATORS_PRESENT)
    put("test_keys_build", IntegritySignal.ROOT_INDICATORS_PRESENT)
    put("which_su_succeeded", IntegritySignal.ROOT_INDICATORS_PRESENT)
    put("root_manager_app_installed", IntegritySignal.ROOT_INDICATORS_PRESENT)

    // ---- runtime.emulator ----
    put("running_on_emulator", IntegritySignal.EMULATOR_DETECTED)

    // ---- runtime.cloner ----
    put("apk_path_mismatch", IntegritySignal.APP_CLONED)
    put("data_dir_mount_invalid", IntegritySignal.APP_CLONED)
    put("uid_mismatch", IntegritySignal.APP_CLONED)
}
