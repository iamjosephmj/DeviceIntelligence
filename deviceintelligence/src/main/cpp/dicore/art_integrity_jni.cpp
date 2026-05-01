// JNI bindings for integrity.art.
//
// The art_integrity module's surface is intentionally narrow: a
// liveness probe (M0), the registry snapshot (M1+), and one
// evaluate entry point in later milestones. Keeping JNI here
// (instead of inside `art_integrity/`) follows the same split as
// `runtime_probe_jni.cpp` and `cloner_probe_jni.cpp` — pure C++
// stays under `dicore/<feature>/`, the Java↔C++ glue lives next
// to its sibling JNI files.
//
// JNI_OnLoad is owned by THIS translation unit because integrity.art's
// snapshot capture HAS to run as early as possible — the whole
// detection model assumes the snapshot is taken before any
// post-load attacker has a chance to touch the values. There is
// no pre-existing JNI_OnLoad anywhere else in dicore today, and
// the Android loader will pick this one up automatically when
// `System.loadLibrary("dicore")` runs from `NativeBridge`'s
// static init block.

#include "art_integrity/access_flags.h"
#include "art_integrity/art_integrity.h"
#include "art_integrity/inline_prologue.h"
#include "art_integrity/jni_entry.h"
#include "art_integrity/jni_env_table.h"
#include "art_integrity/ranges.h"
#include "art_integrity/registry.h"
#include "art_integrity/snapshot.h"
#include "analytics.h"
#include "log.h"
#include "native_integrity/module.h"

#include <cstdio>
#include <jni.h>

namespace dicore {

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
        RLOGE("integrity.art JNI_OnLoad: GetEnv failed");
        // Returning JNI_ERR aborts the load. We'd rather succeed
        // and have integrity.art silently degrade, so fall back to
        // the minimum-supported JNI version and skip the snapshot.
        return JNI_VERSION_1_4;
    }
    art_integrity::initialize(env);
    art_integrity::initialize_jni_env(env);
    art_integrity::initialize_inline_prologue();
    // Vector E + F snapshots depend on the registry being
    // resolved, so they MUST run after `initialize(env)`.
    art_integrity::initialize_jni_entry();
    art_integrity::initialize_access_flags();
    // F19 / NATIVE_INTEGRITY_DESIGN.md — capture libdicore's
    // load address + the system-library range map BEFORE any
    // attacker hook can plausibly land. Same fail-soft pattern:
    // initialize() never throws and never returns an error code;
    // a failure to capture ranges silently degrades the dependent
    // Gx detectors rather than blocking JNI_OnLoad.
    native_integrity::initialize(env);
    // Analytics init: reads opt-out flag, derives client_id, starts
    // background drain thread. Must run after native_integrity so
    // the process state is stable; fail-soft — never blocks the load.
    analytics::init(vm, env);
    return JNI_VERSION_1_6;
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityProbe(
        JNIEnv*, jclass) {
    uint32_t v = art_integrity::probe();
    if (v != art_integrity::kProbeAlive) {
        RLOGE("artIntegrityProbe: unexpected sentinel 0x%08x", v);
    }
    return static_cast<jint>(v);
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityRegistrySize(
        JNIEnv*, jclass) {
    return static_cast<jint>(art_integrity::registry_size());
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityRegistryResolved(
        JNIEnv*, jclass) {
    return static_cast<jint>(art_integrity::resolved_count());
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityEntryPointReadable(
        JNIEnv*, jclass) {
    return static_cast<jint>(art_integrity::entry_point_readable_count());
}

/**
 * Returns a packed `[libart, boot_oat, jit_cache, oat_other]` int
 * array describing how many memory regions of each kind we
 * captured. Used by the M3 CTF flag to assert the resolver picked
 * up at least one libart and one boot OAT mapping on the device.
 */
JNIEXPORT jintArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityRangeCounts(
        JNIEnv* env, jclass) {
    const jint values[4] = {
        static_cast<jint>(art_integrity::libart_range_count()),
        static_cast<jint>(art_integrity::boot_oat_range_count()),
        static_cast<jint>(art_integrity::jit_cache_range_count()),
        static_cast<jint>(art_integrity::other_oat_range_count()),
    };
    jintArray out = env->NewIntArray(4);
    if (!out) return nullptr;
    env->SetIntArrayRegion(out, 0, 4, values);
    return out;
}

/**
 * Vector A — full live scan, returned as a flat String[] where
 * each element is a pipe-delimited record:
 *
 *   "<short_id>|<live_addr_hex>|<snapshot_addr_hex>|<live_class>|<snapshot_class>|<readable>|<drifted>"
 *
 * One element per registry slot, registry-order. Kotlin parses
 * each into [Finding]s — keeps the JNI surface trivial and
 * keeps every wire-format decision Kotlin-side.
 *
 * Returns null only if the JNI allocation fails (which never
 * happens in practice). Empty array means "registry exists but
 * the scan engine couldn't run" (e.g. unknown API offset).
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityScan(
        JNIEnv* env, jclass) {
    art_integrity::ScanEntry entries[art_integrity::kMaxScanEntries];
    const size_t n = art_integrity::scan_live(entries, art_integrity::kMaxScanEntries);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;

    for (size_t i = 0; i < n; ++i) {
        const auto& e = entries[i];
        char buf[256];
        std::snprintf(
            buf, sizeof(buf), "%s|0x%lx|0x%lx|%s|%s|%d|%d",
            e.short_id ? e.short_id : "?",
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.live_entry)),
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.snapshot_entry)),
            art_integrity::classification_name(e.live_class),
            art_integrity::classification_name(e.snapshot_class),
            e.readable ? 1 : 0,
            e.drifted ? 1 : 0);
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

/**
 * Returns true if the most recent [scan_live] call found the
 * baseline storage's hash matching its values. False means an
 * attacker tampered with the baseline page between the last two
 * scans — itself a finding (`art_baseline_tampered`).
 *
 * Returns true on the first scan or when the baseline was just
 * recaptured (no prior baseline to verify).
 */
JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityBaselineIntact(
        JNIEnv*, jclass) {
    return art_integrity::last_scan_baseline_intact() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Vector C — JNIEnv function-table scan. Mirrors the Vector A
 * scan format: one pipe-delimited String per watched function:
 *
 *   "<name>|<live_addr_hex>|<snapshot_addr_hex>|<live_class>|<snapshot_class>|<drifted>"
 *
 * Empty array means the snapshot was never captured (e.g.
 * JNI_OnLoad couldn't get a JNIEnv). Kotlin treats that as
 * "Vector C unavailable" rather than a finding.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityJniEnvScan(
        JNIEnv* env, jclass) {
    art_integrity::JniEnvScanEntry entries[art_integrity::kJniEnvWatched];
    const size_t n = art_integrity::scan_jni_env(env, entries, art_integrity::kJniEnvWatched);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;

    for (size_t i = 0; i < n; ++i) {
        const auto& e = entries[i];
        char buf[256];
        std::snprintf(
            buf, sizeof(buf), "%s|0x%lx|0x%lx|%s|%s|%d",
            e.function_name ? e.function_name : "?",
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.live_fn)),
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.snapshot_fn)),
            art_integrity::classification_name(e.live_class),
            art_integrity::classification_name(e.snapshot_class),
            e.drifted ? 1 : 0);
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

/**
 * Vector C analogue to [artIntegrityBaselineIntact]. Returns
 * true when the JNIEnv-table baseline storage's hash matched
 * its values on the most recent scan.
 */
JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityJniEnvBaselineIntact(
        JNIEnv*, jclass) {
    return art_integrity::last_jni_env_baseline_intact() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Vector D — inline-prologue scan. Each element of the
 * returned String[] is pipe-delimited:
 *
 *   "<symbol>|<addr_hex>|<live_hex_bytes>|<snapshot_hex_bytes>|<resolved>|<drifted>|<baseline_known>|<baseline_mismatch>"
 *
 * Empty array means the snapshot was never captured (extreme
 * edge case — libart unloadable at JNI_OnLoad). Kotlin treats
 * that as "vector D unavailable".
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityInlinePrologueScan(
        JNIEnv* env, jclass) {
    art_integrity::InlinePrologueScanEntry entries[art_integrity::kInlineMaxTargets] = {};
    const size_t n = art_integrity::scan_inline_prologue(
        entries, art_integrity::kInlineMaxTargets);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;

    char livehex[art_integrity::kPrologueBytes * 2 + 1] = {};
    char snaphex[art_integrity::kPrologueBytes * 2 + 1] = {};
    static const char kHex[] = "0123456789abcdef";
    auto hex = [](const uint8_t* in, size_t n_bytes, char* out_buf) {
        for (size_t i = 0; i < n_bytes; ++i) {
            out_buf[i * 2] = kHex[(in[i] >> 4) & 0xF];
            out_buf[i * 2 + 1] = kHex[in[i] & 0xF];
        }
        out_buf[n_bytes * 2] = '\0';
    };
    for (size_t i = 0; i < n; ++i) {
        const auto& e = entries[i];
        hex(e.live, art_integrity::kPrologueBytes, livehex);
        hex(e.snapshot, art_integrity::kPrologueBytes, snaphex);
        char buf[384];
        std::snprintf(
            buf, sizeof(buf), "%s|0x%lx|%s|%s|%d|%d|%d|%d",
            e.symbol ? e.symbol : "?",
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.addr)),
            livehex,
            snaphex,
            e.resolved ? 1 : 0,
            e.drifted ? 1 : 0,
            e.baseline_known ? 1 : 0,
            e.baseline_mismatch ? 1 : 0);
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityInlinePrologueBaselineIntact(
        JNIEnv*, jclass) {
    return art_integrity::last_inline_baseline_intact() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Dev-time helper. Returns one String per Vector-D target with
 * the format `"<symbol>|<api_int>|<hex_bytes>"` (or
 * `<api_int>|missing` if dlsym failed). Used once on each clean
 * device to harvest baselines for the embedded `kBaselines`
 * table in `inline_prologue.cpp`.
 *
 * Not used in production; safe to leave exposed because the
 * contents are derived from libart, which any in-process code
 * could read on its own.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityExtractPrologueBaseline(
        JNIEnv* env, jclass) {
    return art_integrity::extract_baseline_dump(env);
}

/**
 * Vector E — entry_point_from_jni_ scan. Pipe-delimited records,
 * one per registry slot:
 *
 *   "<short_id>|<live_addr_hex>|<snap_addr_hex>|<live_class>|<snap_class>|<readable>|<drifted>|<is_native_by_spec>"
 *
 * Empty array means the snapshot was never captured (e.g. the
 * frozen-method registry didn't initialise). Kotlin treats that
 * as "vector E unavailable" rather than emitting a finding.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityJniEntryScan(
        JNIEnv* env, jclass) {
    art_integrity::JniEntryScanEntry entries[art_integrity::kJniEntryMaxEntries] = {};
    const size_t n = art_integrity::scan_jni_entry(
        entries, art_integrity::kJniEntryMaxEntries);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;

    for (size_t i = 0; i < n; ++i) {
        const auto& e = entries[i];
        char buf[256];
        std::snprintf(
            buf, sizeof(buf), "%s|0x%lx|0x%lx|%s|%s|%d|%d|%d",
            e.short_id ? e.short_id : "?",
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.live_entry)),
            static_cast<unsigned long>(reinterpret_cast<uintptr_t>(e.snapshot_entry)),
            art_integrity::classification_name(e.live_class),
            art_integrity::classification_name(e.snapshot_class),
            e.readable ? 1 : 0,
            e.drifted ? 1 : 0,
            e.is_native_by_spec ? 1 : 0);
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityJniEntryBaselineIntact(
        JNIEnv*, jclass) {
    return art_integrity::last_jni_entry_baseline_intact() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Vector F — access_flags_ scan. Pipe-delimited records, one per
 * registry slot:
 *
 *   "<short_id>|<live_flags_hex>|<snap_flags_hex>|<readable>|<native_flipped_on>|<native_flipped_off>|<any_drift>"
 *
 * Empty array means the snapshot was never captured. Kotlin
 * emits findings only on bit-flips (the cleanest signal); broader
 * `any_drift` is logged but not surfaced as a finding by default
 * because non-attacker code (ART intrinsifier, hot-method
 * marker) does legitimately tweak access_flags_ during runtime.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityAccessFlagsScan(
        JNIEnv* env, jclass) {
    art_integrity::AccessFlagsScanEntry entries[art_integrity::kAccessFlagsMaxEntries] = {};
    const size_t n = art_integrity::scan_access_flags(
        entries, art_integrity::kAccessFlagsMaxEntries);

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(n), strCls, nullptr);
    if (!out) return nullptr;

    for (size_t i = 0; i < n; ++i) {
        const auto& e = entries[i];
        char buf[256];
        std::snprintf(
            buf, sizeof(buf), "%s|0x%x|0x%x|%d|%d|%d|%d",
            e.short_id ? e.short_id : "?",
            e.live_flags, e.snapshot_flags,
            e.readable ? 1 : 0,
            e.native_flipped_on ? 1 : 0,
            e.native_flipped_off ? 1 : 0,
            e.any_drift ? 1 : 0);
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_artIntegrityAccessFlagsBaselineIntact(
        JNIEnv*, jclass) {
    return art_integrity::last_access_flags_baseline_intact() ? JNI_TRUE : JNI_FALSE;
}

}  // extern "C"

}  // namespace dicore
