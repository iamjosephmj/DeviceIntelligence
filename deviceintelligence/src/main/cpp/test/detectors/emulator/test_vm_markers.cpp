// Host unit test for the pure INTEL_0063 marker classifier
// (emu_vm_markers.h). Header-only; compiles standalone.

#include "dicore/detectors/emulator/arch/emu_vm_markers.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

using namespace dicore::vmplat;

int main() {
    // real-device board strings: no markers
    assert(scan_markers("Qualcomm Technologies, Inc. SM8450", 36) == 0);
    assert(scan_markers("Tensor GS201", 12) == 0);
    assert(scan_markers("", 0) == 0);
    assert(scan_markers(nullptr, 0) == 0);

    // QEMU machine: model and compatible forms
    assert(scan_markers("linux,dummy-virt", 16) == kMarkDummyVirt);
    assert(scan_markers("QEMU Virtual Machine", 20) == kMarkQemu);
    const char comp[] = "linux,dummy-virt\0simple-framebuffer\0arm,primecell";
    assert(scan_markers(comp, sizeof(comp)) == kMarkDummyVirt);  // NUL-separated scan

    // case-insensitivity
    assert(scan_markers("qEmU vIrTuAl", 12) == kMarkQemu);

    // goldfish/ranchu (ARM goldfish system images)
    assert(scan_markers("ranchu", 6) == kMarkGoldfish);
    assert(scan_markers("google,ranchu", 13) == kMarkGoldfish);
    assert(scan_markers("goldfish", 8) == kMarkGoldfish);

    // crosvm / cuttlefish
    assert(scan_markers("crosvm", 6) == kMarkCrosvm);
    assert(scan_markers("Android cuttlefish x86_64 phone", 31) == kMarkCuttlefish);

    // combined flags
    {
        const char s[] = "qemu dummy-virt";
        assert(scan_markers(s, sizeof(s) - 1) == (kMarkQemu | kMarkDummyVirt));
    }

    // substring must not match across the boundary: "qemu" inside a longer
    // board name that merely embeds it is still a hit (documented behavior:
    // markers are alerts, backend policy decides) — but a real board string
    // with a coincidental short marker must not double-count
    {
        const char s[] = "taqemus";
        assert(scan_markers(s, 7) == kMarkQemu);  // embedded hit, single flag
    }

    printf("ok: vm marker classifier\n");
    return 0;
}
