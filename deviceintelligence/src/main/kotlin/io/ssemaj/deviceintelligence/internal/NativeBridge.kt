package io.ssemaj.deviceintelligence.internal

/**
 * Thin JNI surface for the native dicore library.
 *
 * All entry points are intentionally low-level: they return raw arrays so
 * the JNI side stays trivial and so we never construct Java collections
 * inside C++ (which is a routine source of leaks and crashes). Kotlin
 * call sites (e.g. [ApkIntegrityDetector]) adapt these into proper
 * collections.
 *
 * The library name is `dicore`; ABI filters in `:deviceintelligence/build.gradle.kts`
 * restrict it to arm64-v8a and x86_64.
 */
internal object NativeBridge {

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var loadError: Throwable? = null

    init {
        try {
            System.loadLibrary("dicore")
            loaded = true
        } catch (t: Throwable) {
            loadError = t
        }
    }

    /** Returns true if libdicore.so loaded and SHA backend is bound. */
    fun isReady(): Boolean = loaded && runCatching { nativeReady() }.getOrDefault(false)

    /** Throwable from the [System.loadLibrary] attempt, if any. */
    fun loadError(): Throwable? = loadError

    @JvmStatic
    external fun nativeReady(): Boolean

    /**
     * Walks the APK at [path] and returns a flat alternating array
     * `[name0, hash0, name1, hash1, ...]` of central-directory entries.
     * Returns null if the APK can't be opened or the central directory
     * can't be found.
     */
    @JvmStatic
    external fun apkEntries(path: String): Array<String>?

    /**
     * Returns SHA-256 hex strings of each v2/v3 signer certificate in the
     * APK at [path]. Returns null if the APK can't be opened, an empty
     * array if no v2/v3 signing block is present.
     */
    @JvmStatic
    external fun apkSignerCertHashes(path: String): Array<String>?

    /**
     * Reads a single Android system property via `__system_property_get`
     * (the same syscall behind `getprop` on the shell). Returns null
     * when the property is unset, the buffer overflows, or the call
     * fails. Used by F16/F17 to read `ro.debuggable`, `ro.build.tags`,
     * etc. without spawning a `getprop` subprocess.
     *
     * Cost: ~10us per call. Safe to call repeatedly; results aren't
     * cached at this layer (the detectors do their own caching).
     */
    @JvmStatic
    external fun systemProperty(name: String): String?

    /**
     * Reads `/proc/self/maps` once and returns the entire contents as
     * a single string (typical size 200-500 KB on a real app).
     * Returns null if the file can't be opened, which on Android
     * effectively never happens — we still null-guard the call sites
     * defensively.
     *
     * Parsing is intentionally deferred to Kotlin to keep the C++
     * side trivial; the cost of one extra UTF-8 conversion is well
     * under a millisecond and only paid once per process.
     */
    @JvmStatic
    external fun procSelfMaps(): String?

    /**
     * F18 milestone-0 liveness probe. Returns the sentinel
     * `0xF18A11FE` when the `art_integrity` translation unit is
     * present in `libdicore.so`. Anything else (including the
     * default Java-side fallback of `0` from a JNI lookup miss)
     * means the build skipped the unit and no F18 vector check
     * can run yet.
     *
     * The probe is the single thing M0 ships on the native side;
     * M1+ adds the real snapshot / evaluate entry points.
     */
    @JvmStatic
    external fun artIntegrityProbe(): Int

    /**
     * F18 — total number of methods in the frozen-method registry
     * (compile-time constant on the native side; surfaced to
     * Kotlin so the detector can compare it against
     * [artIntegrityRegistryResolved] without hard-coding the
     * count in two places).
     */
    @JvmStatic
    external fun artIntegrityRegistrySize(): Int

    /**
     * F18 — number of registry entries that resolved successfully
     * during `JNI_OnLoad`. Equal to [artIntegrityRegistrySize] on
     * a healthy device; lower means at least one JDK class /
     * method we expected to find is unavailable on this OEM ROM,
     * and the corresponding entry will be skipped during scans.
     */
    @JvmStatic
    external fun artIntegrityRegistryResolved(): Int

    /**
     * F18 — number of registry entries whose ArtMethod entry-point
     * pointer was readable at JNI_OnLoad. Less than
     * [artIntegrityRegistryResolved] by the count of INDEX-encoded
     * jmethodIDs (a few intrinsified static native methods on
     * recent ART versions). Vector A's range/diff checks operate
     * only on these readable entries.
     */
    @JvmStatic
    external fun artIntegrityEntryPointReadable(): Int

    /**
     * F18 — `[libart, boot_oat, jit_cache, oat_other]` counts of
     * memory regions captured by the M3 range resolver. A healthy
     * device has libart >= 1 and boot_oat >= 1; jit_cache + other
     * oat are zero on a freshly-launched app and grow as ART
     * compiles methods. Returns null only if the JNI call
     * itself fails, which never happens in practice.
     */
    @JvmStatic
    external fun artIntegrityRangeCounts(): IntArray?

    /**
     * F18 Vector A — re-reads every registry slot's entry pointer
     * NOW and returns one record per slot:
     *
     *   `"<short_id>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<readable>|<drifted>"`
     *
     * Kotlin parses each record into a [Finding] when:
     *   - `readable=1` (otherwise the slot is INDEX-encoded; skip)
     *   - `live_class=unknown` (entry pointer escaped libart/oat/jit;
     *     real Vector A signal)
     *   - `drifted=1` (live != snapshot; M5 signal, the diff check)
     *
     * Empty array means the scanner couldn't initialise (unknown
     * API offset, etc); Kotlin treats that as "vector A
     * unavailable" and emits an inconclusive marker rather than a
     * false-clean.
     */
    @JvmStatic
    external fun artIntegrityScan(): Array<String>?

    /**
     * F18 — `true` when the most recent [artIntegrityScan] call
     * found the mmap-protected baseline page's stored SHA-256
     * matching the recomputed hash of the values. `false` means
     * the baseline was tampered with between the last two scans
     * (an attacker bypassed PROT_NONE and edited the page) —
     * itself a Vector A finding (`art_baseline_tampered`).
     */
    @JvmStatic
    external fun artIntegrityBaselineIntact(): Boolean

    /**
     * F18 Vector C — re-reads the watched JNIEnv function-table
     * pointers (`GetMethodID`, `RegisterNatives`,
     * `CallStaticIntMethod`, etc) NOW and returns one record per
     * watched function:
     *
     *   `"<name>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<drifted>"`
     *
     * Kotlin parses each record into a [Finding] when:
     *   - `live_class=unknown` (pointer escaped libart — Frida-Java
     *     style hijack, emits `jni_env_table_out_of_range`)
     *   - `drifted=1` (live != snapshot, emits `jni_env_table_drifted`)
     *
     * Empty array means the snapshot was never captured (e.g.
     * JNI_OnLoad couldn't get a JNIEnv); Kotlin treats that as
     * "vector C unavailable" rather than a clean signal.
     */
    @JvmStatic
    external fun artIntegrityJniEnvScan(): Array<String>?

    /**
     * F18 Vector C analogue to [artIntegrityBaselineIntact]:
     * `true` when the JNIEnv-table baseline storage's hash
     * matched its values on the most recent scan, `false` if
     * the baseline page was tampered with.
     */
    @JvmStatic
    external fun artIntegrityJniEnvBaselineIntact(): Boolean

    /**
     * F18 Vector D — re-reads the first ~16 bytes of each
     * tracked libart hot-path symbol (`art_quick_invoke_stub`,
     * etc), classifies vs the JNI_OnLoad snapshot AND vs the
     * embedded per-API baseline. Returns one record per slot:
     *
     *   `"<symbol>|<addr_hex>|<live_hex_bytes>|<snap_hex_bytes>|<resolved>|<drifted>|<baseline_known>|<baseline_mismatch>"`
     *
     * Kotlin emits findings when:
     *   - `resolved=1 && drifted=1` → `art_internal_prologue_drifted`
     *     (HIGH; runtime tamper after our snapshot)
     *   - `resolved=1 && baseline_known=1 && baseline_mismatch=1`
     *     → `art_internal_prologue_baseline_mismatch` (MEDIUM;
     *     either a pre-load injector or an unrecognised OEM ROM)
     *
     * Empty array means the snapshot was never captured (libart
     * symbols all missing). Kotlin treats that as "vector D
     * unavailable".
     */
    @JvmStatic
    external fun artIntegrityInlinePrologueScan(): Array<String>?

    /**
     * F18 Vector D analogue to [artIntegrityBaselineIntact]:
     * `true` when the inline-prologue baseline page's stored
     * hash matched its values on the most recent scan.
     */
    @JvmStatic
    external fun artIntegrityInlinePrologueBaselineIntact(): Boolean

    /**
     * F18 dev-time helper. Returns one string per Vector-D
     * target shaped as `"<symbol>|<api_int>|<hex_bytes>"`
     * (or `<api_int>|missing` if dlsym failed for the symbol).
     *
     * Used during M8 baseline-extraction to harvest expected
     * prologue bytes from a clean device, which then get pasted
     * into `inline_prologue.cpp`'s `kBaselines` table. Not
     * referenced by the production detector path; safe to leave
     * exported because the contents are already trivially
     * readable by any in-process code.
     */
    @JvmStatic
    external fun artIntegrityExtractPrologueBaseline(): Array<String>?

    /**
     * F18 Vector E — re-reads `entry_point_from_jni_` (a.k.a. the
     * `data_` slot) for every registry slot and returns one
     * record per slot:
     *
     *   `"<short_id>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<readable>|<drifted>|<snap_was_native>"`
     *
     * Kotlin emits findings when:
     *   - `readable=1` AND `snap_was_native=1` AND `drifted=1`
     *     → `art_method_jni_entry_drifted` (HIGH; canonical
     *     Frida-Java native-method bridge install).
     *   - `readable=1` AND `live_class=unknown`
     *     → `art_method_jni_entry_out_of_range` (HIGH; bridge
     *     pointer landed in attacker-allocated memory, regardless
     *     of method kind).
     *
     * Empty array means the snapshot was never captured (registry
     * empty or per-API offset unknown). Kotlin treats that as
     * "vector E unavailable" rather than a clean signal.
     */
    @JvmStatic
    external fun artIntegrityJniEntryScan(): Array<String>?

    /**
     * F18 Vector E analogue to [artIntegrityBaselineIntact]:
     * `true` when the JNI-entry baseline page's hash matched its
     * values on the most recent scan.
     */
    @JvmStatic
    external fun artIntegrityJniEntryBaselineIntact(): Boolean

    /**
     * F18 Vector F — re-reads `access_flags_` for every registry
     * slot and returns one record per slot:
     *
     *   `"<short_id>|<live_flags_hex>|<snap_flags_hex>|<readable>|<flip_on>|<flip_off>|<any_drift>"`
     *
     * Kotlin emits findings when:
     *   - `readable=1` AND `flip_on=1`
     *     → `art_method_acc_native_flipped_on` (HIGH; Frida-Java
     *     converted a Java method to look native — proof-positive
     *     hook).
     *   - `readable=1` AND `flip_off=1`
     *     → `art_method_acc_native_flipped_off` (HIGH; native
     *     method had its bit cleared — rare but unambiguous
     *     tamper).
     *
     * The `any_drift` field is informational only — ART legitimately
     * tweaks other access_flags_ bits (intrinsic markers, hotness
     * counters historically) during normal execution.
     *
     * Empty array means the snapshot was never captured. Kotlin
     * treats that as "vector F unavailable".
     */
    @JvmStatic
    external fun artIntegrityAccessFlagsScan(): Array<String>?

    /**
     * F18 Vector F analogue to [artIntegrityBaselineIntact]:
     * `true` when the access-flags baseline page's hash matched
     * its values on the most recent scan.
     */
    @JvmStatic
    external fun artIntegrityAccessFlagsBaselineIntact(): Boolean

    /**
     * F19 / NATIVE_INTEGRITY_DESIGN.md G1 — liveness probe for
     * the `native_integrity` translation unit. Returns the
     * sentinel `0xC0DE1170` (`kProbeAlive`) when the unit is
     * linked; anything else means the build skipped it and the
     * G2..G7 detectors will silently degrade.
     */
    @JvmStatic
    external fun nativeIntegrityProbe(): Int

    /**
     * F19 G1 — packed `[libc, libm, libdl, libart, libdicore,
     * other_system]` counts of RX ranges captured by the
     * one-shot `dl_iterate_phdr` walk at JNI_OnLoad. A healthy
     * device shows `libc>=1`, `libdl>=1`, `libart>=1`,
     * `libdicore>=1`. Returns null only if the JNI allocation
     * fails (never observed in practice).
     */
    @JvmStatic
    external fun nativeIntegrityRangeCounts(): IntArray?

    /**
     * F19 G2 — installs the build-time expected `.text` SHA-256
     * (selected from `Fingerprint.dicoreTextSha256ByAbi` for the
     * running ABI) and the build-time `.so` inventory used later
     * by G3. Idempotent. Empty inputs disable the corresponding
     * detector layer (used when the fingerprint blob predates v2
     * and has no per-ABI data).
     *
     * Returns true unconditionally; per-layer success/failure is
     * logged on the native side under the `dicore` tag.
     */
    @JvmStatic
    external fun initNativeIntegrity(
        expectedTextSha256Hex: String,
        expectedSoList: Array<String>,
    ): Boolean

    /**
     * G3 / baseline — declare a directory whose contents the
     * G3 injected-library scan should treat as trusted. Used by
     * the runtime layer at first init to pass the consumer
     * app's `applicationInfo.dataDir` (and the legacy
     * `/data/data/<pkg>` symlink form) so libraries the app
     * legitimately lazy-loads from its own private storage
     * aren't reported as `injected_library`.
     *
     * Idempotent across repeated calls with the same path. The
     * native side normalises trailing slashes.
     *
     * Returns true on accepted input; false only on null input
     * (the Kotlin signature already disallows that, but the
     * native side tolerates malformed paths gracefully).
     */
    @JvmStatic
    external fun addTrustedNativeLibraryDirectory(path: String): Boolean

    /**
     * F19 G2 — recomputes SHA-256 of libdicore's `.text` segment
     * and returns at most two pipe-delimited records the runtime
     * lifts into `native_text_hash_mismatch` (vs build-time) and
     * `native_text_drifted` (vs OnLoad snapshot) findings.
     *
     * Returns:
     *   - null if the snapshot was never captured (G2 unavailable)
     *   - empty array on a clean scan (no findings)
     *   - 1-2 records of shape:
     *       `hash_mismatch|<live_hex>|<expected_hex>`
     *       `drifted|<live_hex>|<snapshot_hex>`
     */
    @JvmStatic
    external fun scanTextIntegrity(): Array<String>?

    /**
     * F19 G3 — re-walks `dl_iterate_phdr` + `/proc/self/maps`,
     * comparing each loaded library against the build-time
     * inventory + system-path allowlist, and each executable
     * mapping against the known-good labels.
     *
     * Returns one pipe-delimited record per flagged hit:
     *   `<kind>|<path_or_anon_addr>|<perms>`
     * Where `kind` is one of `injected_library` (HIGH —
     * unallowlisted post-baseline `.so`),
     * `system_library_late_loaded` (MEDIUM — same as above but the
     * path is rooted in a canonical AOSP system tree, e.g. emulator
     * GL stack lazy-loaded from `/vendor/`), or
     * `injected_anonymous_executable` (HIGH — anonymous /
     * unrecognised RX mapping). Empty array means a clean scan;
     * null means the JNI allocation failed (treated as "skip" by
     * the runtime).
     */
    @JvmStatic
    external fun scanLoadedLibraries(): Array<String>?

    /**
     * F19 G4 — re-reads every snapshotted GOT/`.got.plt` slot
     * in libdicore, classifies its current value via the
     * range map, and returns one pipe-delimited record per
     * flagged slot:
     *   `<slot_idx>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<drifted>|<out_of_range>`
     *
     * Returns:
     *   - null if the GOT snapshot was never captured (G4
     *     unavailable; libdicore stripped, mmap failed, etc).
     *   - empty array on a clean scan.
     *   - 1+ records when slots drifted or resolve outside any
     *     known system library.
     */
    @JvmStatic
    external fun scanGotIntegrity(): Array<String>?

    /**
     * F19 G7 — snapshot accumulated caller-verification violations.
     * Each record is one JNI call into libdicore whose immediate
     * return address resolved outside libart's RX range. Format:
     *   `<jni_function>|<return_addr_hex>|<region_name>`
     *
     * Empty array on a clean device. Returns null only if the
     * JNI allocation fails.
     *
     * Snapshot semantics — records are NOT removed. Two
     * concurrent collect() coroutines (e.g. the background
     * pre-warm and an explicit consumer collect, both running
     * on Dispatchers.IO) both see the full set instead of one
     * "draining" the violation away from the other. Records
     * are deduplicated by `(function, return_address)` at
     * insert time and FIFO-evicted only on cap pressure (256
     * distinct records max).
     */
    @JvmStatic
    external fun snapshotCallerViolations(): Array<String>?

    /**
     * Hands the encoded `TelemetryReport` JSON off to the native
     * analytics drain for delivery to the SDK author's analytics
     * endpoint. Idempotent — the native side enqueues fire-and-forget
     * onto a bounded ring buffer; full buffer or disabled-via-manifest
     * are silently dropped.
     *
     * Called from `TelemetryCollector` immediately after the report is
     * encoded with `TelemetryJson.encode`. The Kotlin layer never holds
     * a reference to the queued payload — once this returns the JVM is
     * free to garbage-collect the JSON string.
     *
     * Wire-shape impact: the analytics document the backend stores has
     * `events.telemetry_report.params` populated with the *exact* JSON
     * the public `DeviceIntelligence.collectJson` API returns, byte-for-
     * byte, so backend dashboards and on-device debug UIs see identical
     * data.
     */
    @JvmStatic
    external fun nativeQueueTelemetryReport(json: String)

    /**
     * Convenience wrapper around [nativeQueueTelemetryReport] that no-ops
     * when the native library failed to load. Letting the call fall
     * through to the unresolved JNI symbol would crash the host app,
     * which is not a tradeoff a telemetry layer should make.
     */
    fun queueTelemetryReport(json: String) {
        if (!loaded) return
        runCatching { nativeQueueTelemetryReport(json) }
    }
}
