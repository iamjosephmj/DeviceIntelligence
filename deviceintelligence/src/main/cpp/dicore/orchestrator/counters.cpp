#include "dicore/orchestrator/counters.h"

#include "dicore/orchestrator/orch_log.h"

#include "dicore/detectors/art_integrity/checks/access_flags.h"
#include "dicore/detectors/art_integrity/checks/inline_prologue.h"
#include "dicore/detectors/art_integrity/checks/jni_entry.h"
#include "dicore/detectors/art_integrity/checks/jni_env_table.h"
#include "dicore/detectors/art_integrity/runtime/ranges.h"
#include "dicore/detectors/art_integrity/runtime/snapshot.h"
#include "dicore/detectors/native_integrity/self/got_verify.h"
#include "dicore/detectors/native_integrity/system_libs/libc_verify.h"
#include "dicore/detectors/native_integrity/system_libs/load_backing.h"
#include "dicore/detectors/native_integrity/self/text_verify.h"

#include <cstddef>
#include <cstdint>

// libc .text integrity is OBSERVE-ONLY (logs, does not count toward the kill)
// until the clean-device zero-drift matrix validates it; then build with
// -DDICORE_LIBC_TEXT_ENFORCE=1 to make a libc_text_hash_mismatch lethal.
#ifndef DICORE_LIBC_TEXT_ENFORCE
#define DICORE_LIBC_TEXT_ENFORCE 0
#endif

// integrity.art vector A ("ArtMethod entry pointer escaped every known ART region")
// is OBSERVE-ONLY (logs, does not count toward INTEL_0012) until a clean-device
// zero-hit matrix validates it; then build with -DDICORE_ART_VECTOR_A_ENFORCE=1.
//
// Unlike vectors C/D/E/F — which compare against a baseline or an embedded
// known-good image, so drift is proof-positive — vector A INFERS a hook from the
// absence of a matching range. That inference is only as sound as the range set,
// and it has now been wrong three times (PRs #3, #4, and the unnamed JIT code
// cache on Android 9 kernels without PR_SET_VMA_ANON_NAME). Observe-only keeps the
// evidence flowing without letting a gap in our own map condemn a clean device.
#ifndef DICORE_ART_VECTOR_A_ENFORCE
#define DICORE_ART_VECTOR_A_ENFORCE 0
#endif

// libc load-backing integrity is OBSERVE-ONLY (logs, does not count toward the
// kill) until the clean-device OEM matrix validates it; then build with
// -DDICORE_LIBC_BACKING_ENFORCE=1 to make a backing mismatch / untrusted apex lethal.
#ifndef DICORE_LIBC_BACKING_ENFORCE
#define DICORE_LIBC_BACKING_ENFORCE 0
#endif

namespace dicore {

// G2/G4 native self-integrity (spec F19). The runtime snapshots are captured at
// JNI_OnLoad; G2 also compares against the build-baked .text hash, which the
// fingerprint __meta row carries (so det_apk installs it before this runs). The
// CRITICAL kinds — native_text_hash_mismatch (the on-disk .so was swapped before
// load) and got_entry_out_of_range (a GOT slot resolves into an attacker page, a
// Frida/PLT-hook trampoline) — count toward the kill. native_text_drifted /
// got_entry_drifted are HIGH and don't kill.
int count_native_integrity_critical() {
    int n = 0;

    // G2 — .text segment vs the build-baked hash.
    native_integrity::TextScan ts{};
    if (native_integrity::scan_text(&ts)) {
        if (ts.expected_known &&
            ts.status_vs_expected == native_integrity::TextStatus::HASH_MISMATCH) {
            ++n;
            ORCH_LOG("orchestrate: CRITICAL native_integrity/native_text_hash_mismatch");
        }
        ORCH_LOG("orchestrate: G2 text scan ok (expected_known=%d vs_expected=%d vs_snapshot=%d)",
              static_cast<int>(ts.expected_known), static_cast<int>(ts.status_vs_expected),
              static_cast<int>(ts.status_vs_snapshot));
    } else {
        ORCH_LOG("orchestrate: G2 text scan unavailable (no snapshot)");
    }

    // G4 (GOT slots), G9 (libc load-backing) and the anon-exec / caller-return
    // scans are REMOVED from the count (false-positive prone): GOT population,
    // lazy binding, JIT and per-device/per-build library variation make them
    // drift on genuine devices without a validated clean-device baseline. Native
    // self-integrity is reduced to the deterministic G2 .text hash of our own lib.

    // G8 — libc .text vs the on-disk libc.so (inline-hook detection). Observe-only
    // by default; counts toward the kill only under DICORE_LIBC_TEXT_ENFORCE.
    native_integrity::LibcTextStatus lt = native_integrity::scan_libc_text();
    if (lt == native_integrity::LibcTextStatus::kHashMismatch) {
#if DICORE_LIBC_TEXT_ENFORCE
        ++n;
        ORCH_LOG("orchestrate: CRITICAL native_integrity/libc_text_hash_mismatch");
#else
        ORCH_LOG("orchestrate: OBSERVE native_integrity/libc_text_hash_mismatch (enforce off)");
#endif
    } else {
        ORCH_LOG("orchestrate: G8 libc text scan status=%s",
                 native_integrity::libc_text_status_name(lt));
    }

    // G9 — libc load-backing (catches a consistent on-disk libc replacement that
    // the G8 .text-vs-disk check is blind to). Observe-only by default; counts
    // toward the kill only under DICORE_LIBC_BACKING_ENFORCE.
    native_integrity::LibcBackingStatus lb = native_integrity::scan_libc_backing();
    if (lb == native_integrity::LibcBackingStatus::kBackingMismatch ||
        lb == native_integrity::LibcBackingStatus::kApexUntrusted) {
        const char* kind = (lb == native_integrity::LibcBackingStatus::kBackingMismatch)
                               ? "libc_backing_mismatch" : "apex_mount_untrusted";
#if DICORE_LIBC_BACKING_ENFORCE
        ++n;
        ORCH_LOG("orchestrate: CRITICAL native_integrity/%s", kind);
#else
        ORCH_LOG("orchestrate: OBSERVE native_integrity/%s (enforce off)", kind);
#endif
        (void)kind;  // kind is referenced only inside ORCH_LOG, which compiles to a no-op in the shipping (silent) build; suppress the unused-variable warning.
    } else {
        ORCH_LOG("orchestrate: G9 libc backing status=%s",
                 native_integrity::libc_backing_status_name(lb));
    }
    return n;
}

// integrity.art — ART method-hooking kill vectors. Only the PROOF-POSITIVE signals
// count, i.e. the ones ART/JIT never produce legitimately, so they don't
// false-crash genuine users. Snapshots are captured at JNI_OnLoad; an unavailable
// scan returns 0 (fail-open).
int count_art_hook_critical(JNIEnv* env) {
    using namespace art_integrity;
    int n = 0;

    // Vectors A and C infer a hook from "this pointer escaped EVERY known ART
    // region". That inference is only sound if we actually know the regions. With an
    // empty range set — /proc/self/maps unreadable, or a hardened, /proc-restricted
    // environment — every pointer classifies UNKNOWN and both vectors would fire on
    // all of their entries at once, marking a device compromised on MISSING EVIDENCE
    // rather than on a finding. That is the one fail-CLOSED path in a detector whose
    // stated contract (above, and orchestrate.cpp) is that an unavailable scan
    // returns 0. ranges.h documents 0 as "ranges unavailable"; honour it here.
    //
    // Vectors D/E/F are unaffected: they compare against a JNI_OnLoad baseline
    // rather than classifying against the range set, so they still run.
    const bool ranges_ok = art_integrity::initialize_ranges() > 0;
    if (!ranges_ok) {
        ORCH_LOG("orchestrate: integrity.art ranges unavailable — vectors A/C skipped (fail-open)");
    }

    // Vector A — ArtMethod entry pointer escaped all known regions.
    if (ranges_ok) {
        ScanEntry e[kMaxScanEntries];
        size_t m = scan_live(e, kMaxScanEntries);
        for (size_t i = 0; i < m; ++i)
            if (e[i].readable && e[i].live_class == Classification::UNKNOWN) {
#if DICORE_ART_VECTOR_A_ENFORCE
                ++n;
#endif
                ORCH_LOG("orchestrate: CRITICAL art/method_entry_hijacked id=%s",
                         e[i].short_id ? e[i].short_id : "?");
            }
    }
    // Vector C — a watched JNIEnv function-table pointer escaped libart.
    if (ranges_ok) {
        JniEnvScanEntry e[kJniEnvWatched];
        size_t m = scan_jni_env(env, e, kJniEnvWatched);
        for (size_t i = 0; i < m; ++i)
            if (e[i].live_class == Classification::UNKNOWN) {
                ++n;
                ORCH_LOG("orchestrate: CRITICAL art/jni_env_table_hijacked fn=%s",
                         e[i].function_name ? e[i].function_name : "?");
            }
    }
    // Vector E — entry_point_from_jni_ (data_) drift. The old exclusion feared
    // `live_class==UNKNOWN` false-firing on non-native core methods (whose `data_`
    // is not a code pointer). We gate STRICTLY on `is_native_by_spec` instead: for
    // a method the JDK declares `native` (e.g. Object#hashCode) `data_` IS the JNI
    // bridge entry and stays libart-resident, so drift there is a proof-positive
    // Frida-Java / data_ hook that cannot occur on a clean device. `readable`
    // skips INDEX-encoded jmethodIDs.
    {
        JniEntryScanEntry e[kJniEntryMaxEntries];
        size_t m = scan_jni_entry(e, kJniEntryMaxEntries);
        for (size_t i = 0; i < m; ++i)
            if (e[i].readable && e[i].drifted && e[i].is_native_by_spec) {
                ++n;
                ORCH_LOG("orchestrate: CRITICAL art/jni_entry_drifted id=%s",
                         e[i].short_id ? e[i].short_id : "?");
            }
    }
    // Vector D — inline trampoline on a watched libart dispatch function (e.g.
    // art::ArtMethod::Invoke). A resolved target whose 16-byte prologue drifts
    // from the JNI_OnLoad snapshot is an inline hook (Frida Interceptor /
    // libsubstrate); libart does not rewrite these prologues at runtime, so drift
    // is proof-positive.
    {
        InlinePrologueScanEntry e[kInlineMaxTargets];
        size_t m = scan_inline_prologue(e, kInlineMaxTargets);
        for (size_t i = 0; i < m; ++i)
            if (e[i].resolved && e[i].drifted) {
                ++n;
                ORCH_LOG("orchestrate: CRITICAL art/inline_prologue_drifted sym=%s",
                         e[i].symbol ? e[i].symbol : "?");
            }
    }

    // Vector F — ACC_NATIVE flipped on (managed method turned into a bridge).
    {
        AccessFlagsScanEntry e[kAccessFlagsMaxEntries];
        size_t m = scan_access_flags(e, kAccessFlagsMaxEntries);
        for (size_t i = 0; i < m; ++i)
            if (e[i].readable && e[i].native_flipped_on) {
                ++n;
                ORCH_LOG("orchestrate: CRITICAL art/method_native_flipped id=%s",
                         e[i].short_id ? e[i].short_id : "?");
            }
    }
    return n;
}

}  // namespace dicore
