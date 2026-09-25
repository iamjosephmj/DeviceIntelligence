// emu_hv_probe.cpp — INTEL_0033 (hypervisor_cpu): x86_64-only CPU-state probe
// for hardware-assisted virtualization.
//
// Why this exists: INTEL_0027 detects binary TRANSLATION (bridge libs, ISA
// divergence). It is silent on emulators that hand guest code to the real
// CPU under hardware virtualization (QEMU/KVM) — the app runs x86_64 libs
// natively, nothing is translated, and the CPU itself "is" the emulator.
// This probe detects THAT: the hypervisor-present CPU state that real
// phone silicon can never report.
//
// Detection (Intel SDM Vol 2, "CPUID"; AMD APM Vol 3):
//   - CPUID.1:ECX[31]      — hypervisor-present bit.
//   - CPUID.0x40000000     — hypervisor vendor leaf (12-byte string).
// A real phone CPU never sets the bit: the leaf range 0x40000000-0x4FFFFFFF
// is reserved by Intel/AMD specifically for hypervisors.
//
// Honest scope (documented for backend policy):
//   - x86_64 Android builds only run on emulators and Chromebooks (ARCVM)
//     and Windows Subsystem for Android — ALL of these set the bit. So on
//     x86_64 this signal means "hardware-virtualized environment", which
//     is true and non-negotiable, but includes legitimate markets.
//   - A determined emulator CAN mask the leaf (QEMU/KVM cpuid masking);
//     default configs do not.
//   - arm64 builds: the probe does not exist there (no CPUID); real ARM
//     devices and ARM KVM hosts are out of scope for this signal.
//
// Every failure path contributes nothing. Fail-open; no finding without
// the bit or a known vendor string.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#if defined(__x86_64__)

#include <cpuid.h>

#include "dicore/platform/obf.h"

namespace dicore {

namespace {

struct HypervisorInfo {
    bool have_leaf1 = false;
    bool hyp_bit = false;
    char vendor[13] = {};       // NUL-terminated 12-byte vendor string
    bool vendor_known = false;  // matches the table below
    uint32_t max_hv_leaf = 0;   // EAX of leaf 0x40000000
    bool have_brand = false;
    char brand[49] = {};        // NUL-terminated 48-byte brand string
    bool brand_hv = false;      // brand contains a hypervisor marker
    bool masked_vendor = false; // vendor leaf answers while the bit is clear
    uint32_t max_std_leaf = 0;  // EAX of leaf 0 (server-side corroboration)
    uint32_t phys_addr_bits = 0;// leaf 0x80000008 EAX[7:0] (corroboration)
};

// Known hypervisor vendor signatures (12-byte IDs, CPUID order EBX:ECX:EDX).
struct VendorId {
    const char* id;
    const char* name;
};
constexpr VendorId kKnownVendors[] = {
    {"KVMKVMKVM", "KVM"},
    {"TCGTCGTCGTCG", "QEMU (TCG, no KVM)"},
    {"VMwareVMware", "VMware"},
    {"XenVMMXenVMM", "Xen HVM"},
    {"Microsoft Hv", "Hyper-V / WSA"},
    {"prl hyperv", "Parallels"},
    {"VBoxVBoxVBox", "VirtualBox"},
    {"ACRNACRNACRN", "ACRN"},
    {"d o t S Y S", "bhyve"},
};

HypervisorInfo probe_hypervisor() {
    HypervisorInfo info{};

    // CPUID leaf 1 — feature flags. ECX bit 31 is the hypervisor-
    // present bit (Intel SDM Vol 2, "CPUID-CPU Identification";
    // AMD APM Vol 3 same).
    uint32_t eax0 = 0, ebx0 = 0, ecx0 = 0, edx0 = 0;
    if (__get_cpuid(0, &eax0, &ebx0, &ecx0, &edx0) != 0)
        info.max_std_leaf = eax0;
    uint32_t eax1 = 0, ebx1 = 0, ecx1 = 0, edx1 = 0;
    info.have_leaf1 = __get_cpuid(1, &eax1, &ebx1, &ecx1, &edx1) != 0;
    info.hyp_bit = info.have_leaf1 && (ecx1 & (1u << 31)) != 0;

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
    // typically returns zeros, and on a hypervisor it returns the
    // vendor string we're looking for.
    uint32_t eax_hv = 0, ebx_hv = 0, ecx_hv = 0, edx_hv = 0;
    __cpuid(0x40000000u, eax_hv, ebx_hv, ecx_hv, edx_hv);
    info.max_hv_leaf = eax_hv;
    char* v = info.vendor;
    __builtin_memcpy(v + 0, &ebx_hv, 4);
    __builtin_memcpy(v + 4, &ecx_hv, 4);
    __builtin_memcpy(v + 8, &edx_hv, 4);

    if (info.hyp_bit || info.vendor[0] != '\0') {
        for (const auto& known : kKnownVendors) {
            // compare only the literal's length: KVM's 12-byte signature is
            // "KVMKVMKVMKVM" while the table entry is the 9-char prefix, and
            // a 12-byte memcmp would read past the literal and under-report
            const size_t idlen = std::strlen(known.id);
            if (idlen <= 12 && std::memcmp(info.vendor, known.id, idlen) == 0) {
                info.vendor_known = true;
                break;
            }
        }
    }

    // Extended leaves: brand string + physical address size. Both pass
    // through from the host on KVM, so they are corroboration for the
    // backend (a "Pixel 8 Pro" token on a QEMU brand is caught server-side)
    // — plus the brand catches the most common masking slip: kvm=off hides
    // the hypervisor leaf but leaves "QEMU Virtual CPU" in the brand.
    uint32_t eax_e = 0;
    __cpuid(0x80000000u, eax_e, ebx_hv, ecx_hv, edx_hv);
    if (eax_e >= 0x80000004u) {
        uint32_t* w = reinterpret_cast<uint32_t*>(info.brand);
        __cpuid(0x80000002u, w[0], w[1], w[2], w[3]);
        __cpuid(0x80000003u, w[4], w[5], w[6], w[7]);
        __cpuid(0x80000004u, w[8], w[9], w[10], w[11]);
        info.have_brand = true;
        static const char* kBrandMarkers[] = {
            "QEMU", "qemu", "KVM", "Virtual", "Microsoft Hv", "Xen",
        };
        for (const auto* m : kBrandMarkers) {
            if (std::strstr(info.brand, m) != nullptr) {
                info.brand_hv = true;
                break;
            }
        }
    }
    uint32_t eax8 = 0, ebx8 = 0, ecx8 = 0, edx8 = 0;
    __cpuid(0x80000008u, eax8, ebx8, ecx8, edx8);
    info.phys_addr_bits = eax8 & 0xffu;

    // Masked-vendor evidence: the 0x40000000 leaf answers (non-zero max
    // leaf) while the architectural bit is clear. Xen PV guests ship this
    // exact shape; a cpuid-masked KVM with a leaked vendor leaf does too.
    if (!info.hyp_bit && info.max_hv_leaf >= 0x40000000u &&
        info.vendor[0] != '\0')
        info.masked_vendor = true;

    return info;
}

}  // namespace

DI_OBF_EMU
std::vector<std::string> emu_hv_records() {
    HypervisorInfo info = probe_hypervisor();

    // Finding rule: any architectural hypervisor evidence fires. A real
    // phone CPU cannot set the bit, answer the vendor leaf, or carry a
    // hypervisor brand. masked_vendor covers cpuid-masked configs whose
    // vendor leaf still answers (Xen PV ships this exact shape).
    const bool fire = info.hyp_bit || info.vendor_known || info.brand_hv ||
                      info.masked_vendor;
    if (!fire) return {};

    std::string r = "hypervisor_cpu";
    r += '\x1f';
    r += "CRITICAL";
    r += '\x1f';
    r += "hvbit=";
    r += info.hyp_bit ? "1" : "0";
    r += "|vendor=";
    r += info.vendor;
    r += "|vendor_known=";
    r += info.vendor_known ? "1" : "0";
    r += "|max_hv_leaf=";
    char leaf[16];
    std::snprintf(leaf, sizeof(leaf), "%u", info.max_hv_leaf);
    r += leaf;
    if (info.masked_vendor) r += "|masked_vendor=1";
    if (info.have_brand) {
        r += "|brand=";
        // keep the detail bounded and printable
        char clean[49];
        for (int i = 0; i < 48; ++i)
            clean[i] = (info.brand[i] >= 32 && info.brand[i] < 127)
                           ? info.brand[i] : ' ';
        clean[48] = '\0';
        r += clean;
        r += info.brand_hv ? "|brand_hv=1" : "";
    }
    char corr[48];
    std::snprintf(corr, sizeof(corr), "|max_std_leaf=%u|pa_bits=%u",
                  info.max_std_leaf, info.phys_addr_bits);
    r += corr;
    return {r};
}

}  // namespace dicore

#else  // !__x86_64__

#include <string>
#include <vector>

namespace dicore {

// The CPUID probe is x86-silicon-only: arm64 builds never execute x86 code,
// and real ARM devices (the overwhelming majority) contribute nothing.
std::vector<std::string> emu_hv_records() {
    return {};
}

}  // namespace dicore

#endif  // __x86_64__
