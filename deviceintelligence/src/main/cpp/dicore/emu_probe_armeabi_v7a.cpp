// emu_probe_armeabi_v7a.cpp — graceful-degrade emulator probe stub
// for 32-bit ARM (armeabi-v7a) builds.
//
// We deliberately do NOT implement the equivalent of the AArch64
// MRS-based probe on 32-bit ARM. Two reasons:
//
//   1. CNTFRQ_EL0 / MIDR_EL1 / REVIDR_EL1 / ID_AA64ISAR0_EL1 are
//      AArch64 system registers — they don't exist on ARMv7. The
//      32-bit equivalents (CP15 c0.c0.0 = MIDR, c14 = generic timer
//      frequency under ARMv7-A virtualization extensions) require
//      `mrc` instructions executed at PL0 only when the kernel
//      explicitly traps and emulates them; many ARMv7 kernels do
//      not, in which case the read raises SIGILL with no clean
//      recovery path inside a security-critical .so.
//
//   2. The QEMU 62.5 MHz CNTFRQ tell that makes the AArch64 probe
//      a single-signal verdict has no equivalent on 32-bit QEMU —
//      QEMU's ARMv7 model emulates the timer at the kernel-set
//      frequency, which is configurable on every userland-visible
//      reading.
//
// The stub fulfils the shared `dicore::emu::Signals probe()`
// contract by returning `present = false`, `decisive = false`, and
// a `raw` string that explicitly records "arch=armeabi-v7a|status=
// unsupported". The `runtime.emulator` detector treats this as
// "no emulator-confirming signal" — matching the behaviour on real
// ARMv7 silicon.
//
// Other detectors (`integrity.apk`, `integrity.bootloader`,
// `attestation.key`, `runtime.environment` including DEX-injection
// channels, `runtime.root`, `runtime.cloner`) are arch-agnostic and
// continue to work normally on this ABI.

#include "emu_probe.h"

#include <cstddef>
#include <cstdio>
#include <cstring>

namespace dicore::emu {

Signals probe() {
    Signals s = {};
    s.present = false;
    s.decisive = false;
    // Match the formatting style of the AArch64 / x86_64 raw dumps so
    // backends parsing telemetry don't have to special-case this ABI.
    std::snprintf(s.raw, sizeof(s.raw),
                  "arch=armeabi-v7a|status=unsupported|hyp=0");
    return s;
}

}  // namespace dicore::emu
