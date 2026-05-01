// JNI bindings for native_integrity. Every Gx milestone of
// NATIVE_INTEGRITY_DESIGN.md exports its scan/init entry points
// here so all of native-integrity's JVM surface lives in a single
// translation unit. JNI_OnLoad itself is owned by
// `art_integrity_jni.cpp` (only one OnLoad per .so); it calls
// `dicore::native_integrity::initialize(env)` which fans out to
// every `initialize_*` declared in this module's headers.
//
// G7 — every JNI entry point below carries a `DI_VERIFY_CALLER()`
// as its first statement. The macro records a
// `native_caller_out_of_range` violation if `__builtin_return_address(0)`
// resolves outside libart's RX range. Future entry points in this
// file MUST follow the same convention; back-filling
// `art_integrity_jni.cpp` and `jni_bridge.cpp` is tracked as a
// separate G7.5 follow-up.

#include "analytics.h"
#include "native_integrity/baseline.h"
#include "native_integrity/caller_verify.h"
#include "native_integrity/caller_verify_macro.h"
#include "native_integrity/got_verify.h"
#include "native_integrity/lib_inventory.h"
#include "native_integrity/module.h"
#include "native_integrity/range_map.h"
#include "native_integrity/text_verify.h"

#include <cstdio>
#include <jni.h>
#include <vector>

namespace dicore {

extern "C" {

/**
 * Called by Kotlin's `TelemetryCollector.collect(...)` immediately after
 * the public `TelemetryReport` is encoded to JSON. Forwards the entire
 * JSON to the native analytics queue as a single `telemetry_report`
 * event, so the backend stores it verbatim under the corresponding run
 * document's `events.telemetry_report.params` field.
 *
 * The C++ analytics layer never inspects the JSON beyond splicing it
 * into the request envelope, so the wire shape on the backend is a
 * 1:1 mirror of what `DeviceIntelligence.collectJson(...)` returns.
 *
 * Null / empty input is a no-op (defensive — the Kotlin signature
 * already disallows null, but the analytics drain ignores empty
 * payloads and we don't want to queue an obviously-broken event).
 */
JNIEXPORT void JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_nativeQueueTelemetryReport(
        JNIEnv* env, jclass, jstring jJson) {
    if (jJson == nullptr) return;
    const char* json = env->GetStringUTFChars(jJson, nullptr);
    if (json == nullptr) return;
    if (json[0] != '\0') {
        analytics::queue_event("telemetry_report", json);
    }
    env->ReleaseStringUTFChars(jJson, json);
}

/**
 * G1 CTF probe. Returns `kProbeAlive` when the native_integrity
 * translation unit is present in `libdicore.so`. Anything else
 * (including the JNI default of 0 from a UnsatisfiedLinkError)
 * means the build skipped the unit and no Gx layer can run.
 */
JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_nativeIntegrityProbe(
        JNIEnv*, jclass) {
    DI_VERIFY_CALLER();
    return static_cast<jint>(native_integrity::probe());
}

/**
 * G1 — packed `[libc, libm, libdl, libart, libdicore, other_system]`
 * counts of RX ranges captured by the range map. Used by the G1
 * CTF assertion in tests / on-device smoke checks; a healthy device
 * shows libc>=1, libdl>=1, libart>=1, libdicore>=1.
 */
JNIEXPORT jintArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_nativeIntegrityRangeCounts(
        JNIEnv* env, jclass) {
    DI_VERIFY_CALLER();
    const jint values[6] = {
        static_cast<jint>(native_integrity::libc_range_count()),
        static_cast<jint>(native_integrity::libm_range_count()),
        static_cast<jint>(native_integrity::libdl_range_count()),
        static_cast<jint>(native_integrity::libart_range_count()),
        static_cast<jint>(native_integrity::libdicore_range_count()),
        static_cast<jint>(native_integrity::other_system_range_count()),
    };
    jintArray out = env->NewIntArray(6);
    if (!out) return nullptr;
    env->SetIntArrayRegion(out, 0, 6, values);
    return out;
}

/**
 * G2 — installs the build-time expected `.text` SHA-256
 * (`Fingerprint.dicoreTextSha256ByAbi[currentAbi]`) and the
 * build-time `.so` inventory used later by G3. Returns true
 * unconditionally today; the per-layer init steps log their
 * own status. Empty inputs are accepted (v1 fingerprint blob
 * has neither value, the dependent checks degrade silently).
 *
 * Idempotent: the runtime calls this once per process from
 * `ApkIntegrityDetector` immediately after a successful
 * fingerprint decode.
 */
JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_initNativeIntegrity(
        JNIEnv* env, jclass,
        jstring jExpectedTextHash, jobjectArray jExpectedSoList) {
    DI_VERIFY_CALLER();
    if (jExpectedTextHash != nullptr) {
        const char* hex = env->GetStringUTFChars(jExpectedTextHash, nullptr);
        if (hex != nullptr) {
            native_integrity::set_expected_text_hash(hex);
            env->ReleaseStringUTFChars(jExpectedTextHash, hex);
        }
    } else {
        native_integrity::set_expected_text_hash(nullptr);
    }
    // G3 — wire the per-ABI build-time `.so` inventory into the
    // injected-library scanner. We pin every UTF chars pointer
    // for the duration of the call so `set_expected_so_inventory`
    // can copy them safely.
    if (jExpectedSoList != nullptr) {
        const jsize n = env->GetArrayLength(jExpectedSoList);
        std::vector<jstring> jstrs;
        std::vector<const char*> cstrs;
        jstrs.reserve(static_cast<size_t>(n));
        cstrs.reserve(static_cast<size_t>(n));
        for (jsize i = 0; i < n; ++i) {
            auto js = static_cast<jstring>(env->GetObjectArrayElement(jExpectedSoList, i));
            if (!js) { cstrs.push_back(nullptr); jstrs.push_back(nullptr); continue; }
            const char* utf = env->GetStringUTFChars(js, nullptr);
            jstrs.push_back(js);
            cstrs.push_back(utf);
        }
        native_integrity::set_expected_so_inventory(
            cstrs.data(), static_cast<size_t>(n));
        for (jsize i = 0; i < n; ++i) {
            if (cstrs[i] != nullptr && jstrs[i] != nullptr) {
                env->ReleaseStringUTFChars(jstrs[i], cstrs[i]);
            }
            if (jstrs[i] != nullptr) env->DeleteLocalRef(jstrs[i]);
        }
    } else {
        native_integrity::set_expected_so_inventory(nullptr, 0);
    }
    return JNI_TRUE;
}

/**
 * G3 / baseline — declare an additional directory whose
 * contents are trusted as legitimate process code. Used by the
 * Kotlin layer at first init to declare the consumer app's
 * `applicationInfo.dataDir` (and the symlinked `/data/data/<pkg>`
 * form) so libraries the app legitimately lazy-loads from its
 * own private storage aren't flagged as injected.
 *
 * Idempotent across repeated calls with the same path; cheap
 * enough to call several times during startup.
 *
 * Returns true on accepted input, false on null/empty.
 */
JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_addTrustedNativeLibraryDirectory(
        JNIEnv* env, jclass, jstring jPath) {
    DI_VERIFY_CALLER();
    if (jPath == nullptr) return JNI_FALSE;
    const char* utf = env->GetStringUTFChars(jPath, nullptr);
    if (utf == nullptr) return JNI_FALSE;
    native_integrity::add_trusted_directory(utf);
    env->ReleaseStringUTFChars(jPath, utf);
    return JNI_TRUE;
}

/**
 * G3 — re-scans `dl_iterate_phdr` + `/proc/self/maps`. Returns
 * one pipe-delimited record per flagged hit, format:
 *
 *   `<kind>|<path_or_anon_addr>|<perms>`
 *
 * Where `kind` is one of `injected_library` /
 * `injected_anonymous_executable` / `system_library_late_loaded`.
 * Empty array means the scan succeeded with no findings (clean
 * device). Returns null only on JNI allocation failure.
 *
 * Capped at 64 records per scan so a pathologically broken
 * system doesn't spam the JNI return array; in practice a clean
 * device returns 0 and an actively-Frida'd device returns 1-3.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_scanLoadedLibraries(
        JNIEnv* env, jclass) {
    DI_VERIFY_CALLER();
    constexpr size_t kCap = 64;
    native_integrity::InventoryRecord records[kCap];
    const size_t n = native_integrity::scan_loaded_libraries(records, kCap);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;
    char buf[600];
    for (size_t i = 0; i < n; ++i) {
        const auto& r = records[i];
        const char* kind;
        switch (r.kind) {
            case native_integrity::InventoryRecord::Kind::INJECTED_LIBRARY:
                kind = "injected_library";
                break;
            case native_integrity::InventoryRecord::Kind::SYSTEM_LIB_LATE_LOADED:
                kind = "system_library_late_loaded";
                break;
            case native_integrity::InventoryRecord::Kind::INJECTED_ANON_EXEC:
            default:
                kind = "injected_anonymous_executable";
                break;
        }
        std::snprintf(buf, sizeof(buf), "%s|%s|%s", kind, r.path, r.perms);
        jstring s = env->NewStringUTF(buf);
        if (!s) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    return out;
}

/**
 * G2 — recomputes SHA-256 of libdicore's `.text` and returns at
 * most two pipe-delimited records:
 *
 *   `hash_mismatch|<live_hex>|<expected_hex>`  — vs build-time
 *   `drifted|<live_hex>|<snapshot_hex>`        — vs OnLoad snapshot
 *
 * Empty array means scan succeeded with no findings (clean device).
 * Returns null only if the snapshot was never captured (G2 layer
 * unavailable), which the Kotlin side treats as "skip" rather
 * than as a finding.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_scanTextIntegrity(
        JNIEnv* env, jclass) {
    DI_VERIFY_CALLER();
    native_integrity::TextScan scan{};
    if (!native_integrity::scan_text(&scan)) {
        return nullptr;
    }

    char livehex[65] = {};
    char snaphex[65] = {};
    char exphex[65] = {};
    static const char kH[] = "0123456789abcdef";
    auto to_hex = [](const uint8_t* in, char* out_buf) {
        for (size_t i = 0; i < 32; ++i) {
            out_buf[i * 2] = kH[(in[i] >> 4) & 0xF];
            out_buf[i * 2 + 1] = kH[in[i] & 0xF];
        }
        out_buf[64] = '\0';
    };
    to_hex(scan.live, livehex);
    to_hex(scan.snapshot, snaphex);
    to_hex(scan.expected, exphex);

    int nrecords = 0;
    char buf0[256];
    char buf1[256];
    if (scan.expected_known &&
        scan.status_vs_expected == native_integrity::TextStatus::HASH_MISMATCH) {
        std::snprintf(buf0, sizeof(buf0), "hash_mismatch|%s|%s", livehex, exphex);
        nrecords = 1;
    }
    if (scan.status_vs_snapshot == native_integrity::TextStatus::DRIFTED) {
        char* dest = (nrecords == 0) ? buf0 : buf1;
        std::snprintf(dest, 256, "drifted|%s|%s", livehex, snaphex);
        nrecords++;
    }

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(nrecords, strCls, nullptr);
    if (!out) return nullptr;
    if (nrecords >= 1) {
        jstring s = env->NewStringUTF(buf0);
        if (!s) return nullptr;
        env->SetObjectArrayElement(out, 0, s);
        env->DeleteLocalRef(s);
    }
    if (nrecords >= 2) {
        jstring s = env->NewStringUTF(buf1);
        if (!s) return nullptr;
        env->SetObjectArrayElement(out, 1, s);
        env->DeleteLocalRef(s);
    }
    return out;
}

/**
 * G4 — re-reads every snapshotted GOT/`.got.plt` slot, classifies
 * its current value, and returns one pipe-delimited record per
 * flagged slot:
 *
 *   `<slot_idx>|<live_hex>|<snap_hex>|<live_class>|<snap_class>|<drifted>|<out_of_range>`
 *
 * Where `<live_class>`/`<snap_class>` are lowercase region names
 * from `range_map::region_name`, and the boolean flags are 0/1.
 *
 * Empty array means a clean scan. Returns null only if the GOT
 * snapshot was never captured (G4 unavailable on this device).
 *
 * Capped at 128 records per scan; deeper hooking would point at
 * a different problem the existing `runtime.environment` finds
 * coarser-grained signals for.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_scanGotIntegrity(
        JNIEnv* env, jclass) {
    DI_VERIFY_CALLER();
    constexpr size_t kCap = 128;
    native_integrity::GotRecord records[kCap];
    const size_t n = native_integrity::scan_got_integrity(records, kCap);
    if (n == SIZE_MAX) return nullptr;

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;
    char buf[256];
    for (size_t i = 0; i < n; ++i) {
        const auto& r = records[i];
        std::snprintf(buf, sizeof(buf),
                      "%u|0x%lx|0x%lx|%s|%s|%d|%d",
                      r.slot_index,
                      static_cast<unsigned long>(r.live_value),
                      static_cast<unsigned long>(r.snapshot_value),
                      native_integrity::region_name(static_cast<native_integrity::Region>(r.live_class)),
                      native_integrity::region_name(static_cast<native_integrity::Region>(r.snapshot_class)),
                      r.drifted ? 1 : 0,
                      r.out_of_range ? 1 : 0);
        jstring s = env->NewStringUTF(buf);
        if (!s) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    return out;
}

/**
 * G7 — snapshot accumulated `caller_verify` violations. Each
 * record is one JNI call whose return address didn't resolve to
 * libart's RX range. Format:
 *
 *   `<function>|<return_addr_hex>|<region_name>`
 *
 * Empty array on a clean device. Returns null only if the JNI
 * allocation fails.
 *
 * Snapshot semantics: records are NOT removed. Two concurrent
 * collect() coroutines (e.g. the background pre-warm and an
 * explicit consumer collect) both see the full set. Records are
 * deduplicated by `(function_name, return_address)` at insert
 * time and FIFO-evicted only on cap pressure (256 distinct
 * records max).
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_snapshotCallerViolations(
        JNIEnv* env, jclass) {
    DI_VERIFY_CALLER();
    constexpr size_t kCap = 256;
    native_integrity::CallerViolation records[kCap];
    const size_t n = native_integrity::snapshot(records, kCap);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;
    char buf[256];
    for (size_t i = 0; i < n; ++i) {
        const auto& r = records[i];
        std::snprintf(buf, sizeof(buf),
                      "%s|0x%lx|%s",
                      r.function_name,
                      static_cast<unsigned long>(r.return_address),
                      native_integrity::region_name(static_cast<native_integrity::Region>(r.return_class)));
        jstring s = env->NewStringUTF(buf);
        if (!s) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    return out;
}

}  // extern "C"

}  // namespace dicore
