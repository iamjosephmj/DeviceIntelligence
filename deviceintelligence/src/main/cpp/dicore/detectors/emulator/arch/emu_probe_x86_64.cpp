// emu_probe_x86_64.cpp — x86_64 CPUID hypervisor probes.
//
// Two CPUID leaves give us a near-airtight emulator detector on x86:
//
//   1. Leaf 1, ECX bit 31 ("hypervisor present"). Intel and AMD
//      explicitly reserved this bit for hypervisors to set; physical
//      silicon never sets it. Every mainstream hypervisor (KVM,
//      Hyper-V, HAXM, WHPX, VMware, Xen, Parallels) sets it. The
//      bit is read-only at EL0 for guest code, so a guest cannot
//      lie about it without a kernel-level intercept that hooks
//      CPUID itself.
//
//   2. Leaf 0x40000000 (the hypervisor vendor leaf, also reserved).
//      Returns the hypervisor's 12-byte ASCII vendor string in
//      EBX:ECX:EDX. Known values:
//        "KVMKVMKVM\0\0\0"   KVM (Linux host, Android Studio emu)
//        "TCGTCGTCGTCG"      QEMU TCG (no acceleration)
//        "Microsoft Hv"      Hyper-V / WHPX
//        "HAXMHAXMHAXM"      Intel HAXM (legacy AS emulator)
//        "VMwareVMware"      VMware
//        "XenVMMXenVMM"      Xen
//        "VBoxVBoxVBox"      VirtualBox
//
// Decision rule (CRITICAL signal):
//   decisive = hypervisor_present_bit && hv_vendor in known set
//
// The `&&` matters: a kernel that defends the hypervisor bit but
// forgets the vendor leaf (or vice versa) would only reveal one
// half. Real silicon reveals neither; emulators reveal both.

#include "dicore/detectors/emulator/emu_probe.h"
#include "dicore/platform/obf.h"  // DI_OBF_EMU — hide the hypervisor-bit/vendor decision

#include <cpuid.h>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace {

void append_fmt(char* buf, size_t cap, size_t* offset, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

void append_fmt(char* buf, size_t cap, size_t* offset, const char* fmt, ...) {
    if (*offset >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(buf + *offset, cap - *offset, fmt, ap);
    va_end(ap);
    if (written < 0) return;
    size_t advance = static_cast<size_t>(written);
    if (*offset + advance >= cap) {
        *offset = cap - 1;
    } else {
        *offset += advance;
    }
}

// Return true if [vendor] (12 ASCII bytes, possibly NUL-padded)
// matches a known hypervisor vendor. Not a regex / fuzzy match —
// we only want to count a signal if the hypervisor self-identifies
// with one of the strings we've vetted.
bool is_known_hypervisor_vendor(const char vendor[12]) {
    static constexpr const char* kKnown[] = {
        "KVMKVMKVM\0\0\0",
        "TCGTCGTCGTCG",
        "Microsoft Hv",
        "HAXMHAXMHAXM",
        "VMwareVMware",
        "XenVMMXenVMM",
        "VBoxVBoxVBox",
    };
    for (const char* k : kKnown) {
        if (std::memcmp(vendor, k, 12) == 0) return true;
    }
    return false;
}

}  // namespace

namespace dicore::emu {

DI_OBF_EMU
Signals probe() {
    Signals s{};

    // CPUID leaf 0 — base vendor string (always available; gives us
    // GenuineIntel / AuthenticAMD on real silicon, which is useful
    // telemetry even though we don't gate on it).
    uint32_t eax0 = 0, ebx0 = 0, ecx0 = 0, edx0 = 0;
    char base_vendor[13] = {};
    bool have_leaf0 = __get_cpuid(0, &eax0, &ebx0, &ecx0, &edx0) != 0;
    if (have_leaf0) {
        std::memcpy(base_vendor + 0, &ebx0, 4);
        std::memcpy(base_vendor + 4, &edx0, 4);
        std::memcpy(base_vendor + 8, &ecx0, 4);
    }

    // CPUID leaf 1 — feature flags. ECX bit 31 is the hypervisor-
    // present bit (Intel SDM Vol 2, "CPUID-CPU Identification";
    // AMD APM Vol 3 same).
    uint32_t eax1 = 0, ebx1 = 0, ecx1 = 0, edx1 = 0;
    bool have_leaf1 = __get_cpuid(1, &eax1, &ebx1, &ecx1, &edx1) != 0;
    bool hyp_bit = have_leaf1 && (ecx1 & (1u << 31)) != 0;

    // CPUID leaf 0x40000000 — hypervisor vendor leaf. EAX returns
    // the maximum hypervisor leaf, EBX:ECX:EDX the 12-byte vendor
    // string.
    //
    // We MUST NOT use __get_cpuid here — it does an internal bounds
    // check against leaf 0's "max standard leaf" return and refuses
    // to issue CPUID for any leaf above 0x80000000 unless leaf
    // 0x80000000 explicitly advertises it. The hypervisor leaf range
    // 0x40000000-0x4FFFFFFF is reserved by Intel/AMD specifically
    // *for* hypervisors and is never advertised by the standard
    // leaves, so __get_cpuid always rejects it. The lower-level
    // __cpuid macro just emits the instruction with no bounds check,
    // which is what we want: on real silicon the hypervisor leaf
    // typically returns zeros (no match against kKnown), and on a
    // hypervisor it returns the vendor string we're looking for.
    uint32_t eax_hv = 0, ebx_hv = 0, ecx_hv = 0, edx_hv = 0;
    __cpuid(0x40000000u, eax_hv, ebx_hv, ecx_hv, edx_hv);
    char hv_vendor[13] = {};
    std::memcpy(hv_vendor + 0, &ebx_hv, 4);
    std::memcpy(hv_vendor + 4, &ecx_hv, 4);
    std::memcpy(hv_vendor + 8, &edx_hv, 4);
    bool hv_vendor_known = is_known_hypervisor_vendor(hv_vendor);

    s.present = hyp_bit || hv_vendor_known;
    s.decisive = hyp_bit && hv_vendor_known;

    // Render the hypervisor vendor as a printable string for the UI:
    // strip non-printable bytes so a malformed leaf doesn't poison
    // the log line.
    char hv_printable[13] = {};
    for (int i = 0; i < 12; ++i) {
        char c = hv_vendor[i];
        hv_printable[i] = (c >= 0x20 && c < 0x7F) ? c : '.';
    }

    size_t off = 0;
    append_fmt(s.raw, sizeof(s.raw), &off, "arch=x86_64");
    append_fmt(s.raw, sizeof(s.raw), &off, "|vendor=%s",
               have_leaf0 ? base_vendor : "?");
    append_fmt(s.raw, sizeof(s.raw), &off, "|hyp=%d", hyp_bit ? 1 : 0);
    append_fmt(s.raw, sizeof(s.raw), &off, "|hv_vendor=%s", hv_printable);
    append_fmt(s.raw, sizeof(s.raw), &off, "|hv_max_leaf=0x%x", eax_hv);

    return s;
}

}  // namespace dicore::emu
