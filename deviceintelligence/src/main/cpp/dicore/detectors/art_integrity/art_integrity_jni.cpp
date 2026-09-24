// JNI_OnLoad for libdicore — the earliest in-process hook.
//
// This translation unit owns JNI_OnLoad (the Android loader calls it when
// `System.loadLibrary("dicore")` runs from NativeBridge's static init). It runs
// before any post-load attacker code, so it is where every snapshot/baseline is
// captured and where the enforcement watchdog is forked.
//
// The art_integrity scan ENTRY POINTS that used to live here were removed with the
// Kotlin detectors; the art_integrity::initialize* snapshot calls remain, and load
// ordering still matters (Vectors E and F must run after initialize(env)).
//
// The scan cores are NOT dormant — an earlier version of this comment said they were.
// orchestrator/counters.cpp::count_art_hook_critical() calls all five scans on every
// challenge, and their result is pushed as a CRITICAL `art/art_hook_critical` record
// (INTEL_0001) by dicore_verdict(). It demonstrably fires: two false positives were fixed in
// PRs #3 and #4 after it flagged clean devices.

#include "dicore/detectors/art_integrity/checks/access_flags.h"
#include "dicore/detectors/art_integrity/art_integrity.h"
#include "dicore/detectors/art_integrity/checks/inline_prologue.h"
#include "dicore/detectors/art_integrity/checks/jni_entry.h"
#include "dicore/detectors/art_integrity/checks/jni_env_table.h"
#include "dicore/detectors/art_integrity/runtime/ranges.h"
#include "dicore/detectors/art_integrity/runtime/registry.h"
#include "dicore/detectors/art_integrity/runtime/snapshot.h"
#include "dicore/platform/framework_shim.h"
#include "dicore/jni/jni_anchors.h"
#include "dicore/jni/jni_cache.hpp"
#include "dicore/platform/log.h"
#include "dicore/detectors/native_integrity/module.h"
#include "dicore/jni/reentry_guard.h"
#include "dicore/platform/syscalls.h"
#include <cstring>

#include <atomic>
#include <cstdlib>
#include <jni.h>

// (seed-decryptable) even when exec-page resolution fails.

namespace dicore {


extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    // A2: anti-reentrant gate — MUST precede every other statement so a
    // re-entry aborts before any state is touched. The attack campaign's
    // re-trigger technique re-invoked JNI_OnLoad inside an already-loaded
    // library to re-run the captures below against attacker-controlled
    // memory (laundering hooks into the baselines). First entry arms the gate
    // and proceeds; any later entry finds it armed and dies here.
    static std::atomic<uint32_t> g_onload_gate{0};
    if (!dicore::reentry::arm(g_onload_gate)) abort();
    // anything reads the strenc strings. On 16K-page devices the load-time
    // key resolution fails and the first FindClass aborts on ciphertext —
    // this dump captures the exact VMA/offset geometry that resolution saw,
    // from a context proven to reach logcat.
    {
        int errno_out = 0;
        int fd = dicore::sys::raw_openat(-100 /*AT_FDCWD*/, "/proc/self/maps",
                                        0 /*O_RDONLY*/, 0, &errno_out);
        if (fd >= 0) {
            char buf[8192];
            ssize_t n;
            size_t keep = 0;
            int dumped = 0;
            while ((n = dicore::sys::raw_read_full(fd, buf + keep,
                                                  sizeof(buf) - keep, &errno_out)) > 0 &&
                   dumped < 60) {
                size_t total = keep + static_cast<size_t>(n);
                size_t line_start = 0;
                for (size_t i = 0; i < total; i++) {
                    if (buf[i] != '\n') continue;
                    buf[i] = '\0';
                    const char* line = buf + line_start;
                    if (dumped < 60 && std::strstr(line, "base.apk")) {
                        dumped++;
                    }
                    line_start = i + 1;
                }
                keep = total - line_start;
                std::memmove(buf, buf + line_start, keep);
            }
            dicore::sys::raw_close(fd);
        } else {
        }
    }
    // Cache the VM so the native orchestrator can up-call the FrameworkShim
    // (spec 03 §1). Safe to set first; the rest of OnLoad still runs.
    framework_shim_set_vm(vm);
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
        RLOGE("integrity.art JNI_OnLoad: GetEnv failed");
        // Returning JNI_ERR aborts the load. We'd rather succeed
        // and have integrity.art silently degrade, so fall back to
        // the minimum-supported JNI version and skip the snapshot.
        return JNI_VERSION_1_4;
    }
    // B1: snapshot the JNIEnv function table into the .bss cache BEFORE any
    // bridge call site runs — every wired env-> call below (anchor
    // registration included) then reads the snapshot, not the live
    // (patchable) vtable. Fail-soft is impossible here by design: if GetEnv
    // failed we never reach this line, and capture itself is plain reads.
    jni_cache::initialize(env);
    // Bind the tech.thessemaj.deviceintelligence.dx.NativeBridge anchors dynamically (spec 08 Stage C) instead of
    // exporting Java_* symbols. Fail-soft: a registration failure leaves the
    // natives unbound and is logged, but never aborts the load.
    if (!register_k_anchors(env)) {
        RLOGE("anchor registration failed");
    }
    // MUST be first, and MUST be here rather than lazily at scan time: it records
    // which anonymous executable regions existed BEFORE any post-load code ran, so
    // ART's unnamed JIT code cache is distinguishable from a stub mapped later. A
    // lazy capture would baseline the attacker's memory along with ART's.
    art_integrity::initialize_anon_exec_baseline();
    art_integrity::initialize(env);
    art_integrity::initialize_jni_env(env);
    art_integrity::initialize_inline_prologue();
    // Vector E + F snapshots depend on the registry being
    // resolved, so they MUST run after `initialize(env)`.
    art_integrity::initialize_jni_entry();
    art_integrity::initialize_access_flags();
    // the native-integrity design — capture libdicore's
    // load address + the system-library range map BEFORE any
    // attacker hook can plausibly land. Same fail-soft pattern:
    // initialize() never throws and never returns an error code;
    // a failure to capture ranges silently degrades the dependent
    // Gx detectors rather than blocking JNI_OnLoad.
    native_integrity::initialize(env);
    return JNI_VERSION_1_6;
}

}  // extern "C"

}  // namespace dicore
