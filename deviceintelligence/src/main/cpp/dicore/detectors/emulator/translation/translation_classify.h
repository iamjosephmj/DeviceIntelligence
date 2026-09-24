#pragma once

// Pure classifier: is THIS PROCESS running under instruction-set translation,
// or on a kernel of the wrong ISA family?
//
// The question answered here is definitional, not heuristic:
//   - `uname().machine` reports the KERNEL's ISA. A process built for arm64
//     cannot execute on an x86 kernel unless a translation layer (libhoudini /
//     libndk_translation) rewrites every instruction — that is what LDPlayer /
//     BlueStacks / Nox / MuMu "ARM mode" and Genymotion-on-x86 are.
//   - `ro.dalvik.vm.native.bridge` is "0"/empty on genuine phones; naming a
//     known translation bridge means the image ships one.
//   - A known bridge lib mapped into OUR /proc/self/maps means our own process
//     is executing translated code right now.
// None of these can occur on genuine silicon (the sanctioned-translation
// exception — ChromeOS/ARC — is itself a virtual environment that already
// trips INTEL_0044 software attestation, so it is not a new landing zone).
//
// Everything here is pure string classification over attacker-influenced
// inputs: host-testable (test/detectors/emulator/) and fuzzable
// (fuzz/fuzz_translation.cpp). Unparseable input contributes nothing —
// fail-open, never a guess.

#include <string>

namespace dicore {
namespace emu {

struct TranslationFinding {
    bool affirmative = false;         // any sub-fact fired -> emit a record
    bool process_translated = false;  // uname machine ISA family != process ABI family
    bool bridge_named = false;        // native-bridge prop names a known translation lib
    bool bridge_mapped = false;       // a known translation lib is mapped into this process
    char machine[40] = {0};           // echo of the uname machine string (record detail)
    char bridge[96] = {0};            // echo of the native-bridge prop value (record detail)
};

// ISA family of a uname `machine` string: 1 = ARM, 2 = x86, 0 = unknown
// (unknown always fails open — no finding). Exposed for tests.
int machine_isa_family(const char* machine);

// The classifier proper. `process_family` is 1/2/0 (see machine_isa_family);
// translation_probe.cpp passes the compile-time ABI family, tests pass
// synthesized values. `proc_maps` is the /proc/self/maps blob (may be empty —
// the maps sub-fact then simply contributes nothing).
TranslationFinding classify_translation_for(int process_family,
                                            const char* machine,
                                            const char* bridge_prop,
                                            const std::string& proc_maps);

// Convenience wrapper: classify with THIS build's process ABI.
TranslationFinding classify_translation(const char* machine,
                                        const char* bridge_prop,
                                        const std::string& proc_maps);

}  // namespace emu
}  // namespace dicore
