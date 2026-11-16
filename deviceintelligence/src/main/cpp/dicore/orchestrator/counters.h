#pragma once

#include <jni.h>

// The two verdict cores that count CRITICALs directly (rather than emitting
// US-framed records): native self-integrity (G2/G4) and ART method-hooking. They
// Both are called directly from dicore_verdict() in orchestrate.cpp. Extracted verbatim
// from dicore_orchestrate.cpp.

namespace dicore {

// G2/G4 native self-integrity (spec F19). CRITICAL kinds:
//   native_text_hash_mismatch  — the on-disk .so was swapped before load
//   got_entry_out_of_range     — a GOT slot resolves into an attacker page
// (native_text_drifted / got_entry_drifted are HIGH and do NOT count.)
int count_native_integrity_critical();

// integrity.art — ART method-hooking proof-positive vectors (the signals ART/JIT
// never produce legitimately): method entry pointer escaped every known RX region,
// a watched JNIEnv table pointer escaped libart, or ACC_NATIVE flipped on.
int count_art_hook_critical(JNIEnv* env);

}  // namespace dicore
