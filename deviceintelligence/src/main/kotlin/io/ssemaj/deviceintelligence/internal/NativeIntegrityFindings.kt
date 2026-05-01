package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * Builders for the new `runtime.environment` finding kinds added by
 * `NATIVE_INTEGRITY_DESIGN.md`. Centralised so:
 *
 *  1. `RuntimeEnvironmentDetector` stays focused on orchestration —
 *     each scan boils down to "call [NativeBridge].xxx, lift the
 *     pipe-delimited records into Findings via this helper, append".
 *  2. The exact `kind` strings, severity choices, and `details`
 *     keys live in one place. Backends pivoting on them should be
 *     able to grep this file to enumerate the full vocabulary.
 *
 * Each builder is a pure function over its inputs (no I/O, no
 * mutable global state) so it's trivial to unit-test the lifting
 * logic without standing up the JNI layer.
 */
internal object NativeIntegrityFindings {

    // Stable wire constants — backend teams pivot on these.
    const val KIND_NATIVE_TEXT_HASH_MISMATCH: String = "native_text_hash_mismatch"
    const val KIND_NATIVE_TEXT_DRIFTED: String = "native_text_drifted"
    const val KIND_INJECTED_LIBRARY: String = "injected_library"
    const val KIND_INJECTED_ANONYMOUS_EXECUTABLE: String = "injected_anonymous_executable"

    /**
     * A library that wasn't on the JNI_OnLoad baseline AND wasn't on
     * the build-time inventory, but whose absolute path is rooted in
     * a canonical AOSP system tree (`/system/`, `/system_ext/`,
     * `/product/`, `/odm/`, `/vendor/`, `/apex/`,
     * `/data/dalvik-cache/`).
     *
     * Common on emulators (the `/vendor/lib64/` GL emulation pipeline
     * is lazy-loaded after `JNI_OnLoad` and therefore misses the
     * baseline) and on OEMs that defer vendor HAL initialisation. We
     * intentionally don't drop the finding — it's still useful
     * forensic context — but we surface it at MEDIUM severity rather
     * than HIGH because the read-only system partitions are
     * dm-verity-protected and tampering with them requires
     * bootloader-unlock + remount, which is independently caught by
     * `runtime.root` / `integrity.bootloader` / `attestation.key`.
     *
     * Crucially this kind is NOT mapped to
     * [IntegritySignal.INJECTED_NATIVE_CODE] in the high-level signal
     * roll-up: a clean emulator must not trip the high-level
     * "injected native code" signal just because the GL stack was
     * lazy-loaded.
     */
    const val KIND_SYSTEM_LIBRARY_LATE_LOADED: String = "system_library_late_loaded"
    const val KIND_GOT_ENTRY_DRIFTED: String = "got_entry_drifted"
    const val KIND_GOT_ENTRY_OUT_OF_RANGE: String = "got_entry_out_of_range"
    const val KIND_STACK_FOREIGN_FRAME: String = "stack_foreign_frame"
    const val KIND_NATIVE_CALLER_OUT_OF_RANGE: String = "native_caller_out_of_range"

    /**
     * Lifts one pipe-delimited record from
     * `NativeBridge.scanTextIntegrity()` into a [Finding]. Returns
     * null if the record is malformed (defensive — the native side
     * should never emit garbage but we don't want a single bad
     * record to crash the detector).
     *
     * Record formats (kind|hex|hex):
     *   `hash_mismatch|<live_hex>|<expected_hex>` — vs build-time
     *   `drifted|<live_hex>|<snapshot_hex>`       — vs OnLoad snapshot
     */
    fun textFinding(record: String, subject: String?): Finding? {
        val parts = record.split('|')
        if (parts.size != 3) return null
        val (kindTag, liveHex, otherHex) = parts
        return when (kindTag) {
            "hash_mismatch" -> Finding(
                kind = KIND_NATIVE_TEXT_HASH_MISMATCH,
                severity = Severity.CRITICAL,
                subject = subject,
                message = "libdicore.so .text section SHA-256 differs from the build-time baseline",
                details = mapOf(
                    "live_sha256" to liveHex,
                    "expected_sha256" to otherHex,
                    "source" to "scan_text_integrity",
                ),
            )
            "drifted" -> Finding(
                kind = KIND_NATIVE_TEXT_DRIFTED,
                severity = Severity.HIGH,
                subject = subject,
                message = "libdicore.so .text section SHA-256 drifted from the JNI_OnLoad snapshot",
                details = mapOf(
                    "live_sha256" to liveHex,
                    "snapshot_sha256" to otherHex,
                    "source" to "scan_text_integrity",
                ),
            )
            else -> null
        }
    }

    /**
     * Lifts one pipe-delimited record from
     * `NativeBridge.scanLoadedLibraries()` into a [Finding].
     * Returns null if the record is malformed.
     *
     * Record formats (kind|path|perms):
     *   `injected_library|<absolute_so_path>|`                 (perms empty)
     *   `system_library_late_loaded|<absolute_so_path>|`       (perms empty)
     *   `injected_anonymous_executable|<anon_descriptor>|<perms>`
     */
    fun loadedLibraryFinding(record: String, subject: String?): Finding? {
        val parts = record.split('|')
        if (parts.size != 3) return null
        val (kindTag, path, perms) = parts
        return when (kindTag) {
            "injected_library" -> Finding(
                kind = KIND_INJECTED_LIBRARY,
                severity = Severity.HIGH,
                subject = subject,
                message = "Library loaded into the process is not on the build-time inventory and " +
                    "doesn't live under any allowlisted system path",
                details = mapOf(
                    "library_path" to path,
                    "source" to "scan_loaded_libraries",
                ),
            )
            "system_library_late_loaded" -> Finding(
                kind = KIND_SYSTEM_LIBRARY_LATE_LOADED,
                severity = Severity.MEDIUM,
                subject = subject,
                message = "System library was not present at JNI_OnLoad and isn't on the build-time " +
                    "inventory, but lives under a read-only AOSP system partition (`/system/`, " +
                    "`/vendor/`, `/apex/`, …) — almost always a vendor library lazy-loaded after " +
                    "process start; kept for forensic completeness",
                details = mapOf(
                    "library_path" to path,
                    "source" to "scan_loaded_libraries",
                ),
            )
            "injected_anonymous_executable" -> Finding(
                kind = KIND_INJECTED_ANONYMOUS_EXECUTABLE,
                severity = Severity.HIGH,
                subject = subject,
                message = "Anonymous (or unknown-bracketed) executable mapping in the process — " +
                    "canonical fingerprint of an in-process JIT hooker / staged shellcode region",
                details = mapOf(
                    "mapping" to path,
                    "permissions" to perms,
                    "source" to "scan_loaded_libraries",
                ),
            )
            else -> null
        }
    }

    /**
     * Lifts one record from `NativeBridge.scanGotIntegrity()` into
     * up to two Findings:
     *
     *   - `got_entry_drifted`     (HIGH)     when `<drifted>=1`
     *   - `got_entry_out_of_range` (CRITICAL) when `<out_of_range>=1`
     *
     * Both can fire from the same record (a GOT slot that drifted
     * AND now points outside any known library is the strongest
     * signal of an active hook). Returns the list, possibly empty.
     *
     * Record format (7 fields, pipe-delimited):
     *   `<slot_idx>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<drifted>|<out_of_range>`
     */
    fun gotIntegrityFindings(record: String, subject: String?): List<Finding> {
        val parts = record.split('|')
        if (parts.size != 7) return emptyList()
        val slotIdx = parts[0]
        val liveHex = parts[1]
        val snapHex = parts[2]
        val liveClass = parts[3]
        val snapClass = parts[4]
        val drifted = parts[5] == "1"
        val outOfRange = parts[6] == "1"
        if (!drifted && !outOfRange) return emptyList()
        val details = mapOf(
            "slot_index" to slotIdx,
            "live_value" to liveHex,
            "snapshot_value" to snapHex,
            "live_classification" to liveClass,
            "snapshot_classification" to snapClass,
            "source" to "scan_got_integrity",
        )
        val out = ArrayList<Finding>(2)
        if (outOfRange) {
            out += Finding(
                kind = KIND_GOT_ENTRY_OUT_OF_RANGE,
                severity = Severity.CRITICAL,
                subject = subject,
                message = "GOT slot $slotIdx in libdicore.so resolves to an address outside every " +
                    "known system library (likely a hook trampoline)",
                details = details,
            )
        }
        if (drifted) {
            out += Finding(
                kind = KIND_GOT_ENTRY_DRIFTED,
                severity = Severity.HIGH,
                subject = subject,
                message = "GOT slot $slotIdx in libdicore.so changed value since the JNI_OnLoad snapshot",
                details = details,
            )
        }
        return out
    }

    /**
     * Builds a `stack_foreign_frame` finding from a [StackGuard]
     * (deterministic) or `StackWatchdog` (sampled) violation.
     * The same finding kind is shared across both sources; the
     * `source` field in `details` distinguishes them so backend
     * pivots can treat them differently if needed.
     */
    /**
     * Lifts one record from `NativeBridge.snapshotCallerViolations()`
     * into a [Finding].
     *
     * Record format (3 fields, pipe-delimited):
     *   `<jni_function>|<return_addr_hex>|<region_name>`
     */
    fun callerOutOfRangeFinding(record: String, subject: String?): Finding? {
        val parts = record.split('|')
        if (parts.size != 3) return null
        val (functionName, returnAddrHex, regionName) = parts
        return Finding(
            kind = KIND_NATIVE_CALLER_OUT_OF_RANGE,
            severity = Severity.HIGH,
            subject = subject,
            message = "JNI entry point $functionName was called with a return address outside " +
                "libart's RX range (resolved to $regionName) — likely a native trampoline wrapping " +
                "the JNI bridge",
            details = mapOf(
                "jni_function" to functionName,
                "return_address" to returnAddrHex,
                "return_classification" to regionName,
                "source" to "snapshot_caller_violations",
            ),
        )
    }

    fun stackForeignFrameFinding(
        violation: StackGuard.Violation,
        subject: String?,
    ): Finding = Finding(
        kind = KIND_STACK_FOREIGN_FRAME,
        severity = Severity.HIGH,
        subject = subject,
        message = "Foreign class on the call stack of ${violation.hookedMethod} — likely a Kotlin / " +
            "Java method hook (Xposed / LSPosed / SandHook / Pine / Frida script)",
        details = mapOf(
            "hooked_method" to violation.hookedMethod,
            "foreign_class" to violation.foreignFrame.className,
            "foreign_method" to violation.foreignFrame.methodName,
            "foreign_file" to (violation.foreignFrame.fileName ?: ""),
            "foreign_line" to violation.foreignFrame.lineNumber.toString(),
            "source" to violation.source,
        ),
    )
}
