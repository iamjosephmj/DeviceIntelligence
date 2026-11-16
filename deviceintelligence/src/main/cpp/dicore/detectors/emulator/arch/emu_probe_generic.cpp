// emu_probe_generic.cpp — fallback CPU emulator probe for ABIs without a
// dedicated implementation (armeabi-v7a 32-bit ARM, x86 32-bit).
//
// The arm64 (CNTFRQ_EL0) and x86_64 (CPUID hypervisor leaf) probes read
// architectural state that doesn't have a clean, low-risk 32-bit analogue we've
// validated on-device (32-bit ARM CNTFRQ is a CP15 access that traps to SIGILL
// on some kernels; 32-bit x86 isn't shipped — abiFilters has no x86). Rather
// than leave a SILENT no-op (the exact class of ABI gap that made the watchdog
// kill ineffective on x86_64/arm32 before — see watchdog.cpp), this fallback is
// EXPLICIT: it reports "unsupported" and never claims decisive. Emulator
// coverage on these ABIs is carried by the attestation core
// (software_attestation_only), which already CRITICALs an emulator regardless of
// CPU probe. A real CP15-CNTFRQ probe for armeabi-v7a is a possible follow-up.

#include "dicore/detectors/emulator/emu_probe.h"

#include <cstdio>

namespace dicore::emu {

Signals probe() {
    Signals s{};
    s.present = false;
    s.decisive = false;
#if defined(__arm__)
    snprintf(s.raw, sizeof(s.raw), "arch=armeabi-v7a|cpu_probe=unsupported");
#elif defined(__i386__)
    snprintf(s.raw, sizeof(s.raw), "arch=x86|cpu_probe=unsupported");
#else
    snprintf(s.raw, sizeof(s.raw), "arch=unknown|cpu_probe=unsupported");
#endif
    return s;
}

}  // namespace dicore::emu
