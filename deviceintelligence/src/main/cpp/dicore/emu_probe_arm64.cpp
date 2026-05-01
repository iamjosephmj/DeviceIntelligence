// emu_probe_arm64.cpp — AArch64 system-register emulator probes.
//
// Reads architectural state that QEMU/KVM can't fake without
// modifying its register-emulation layer:
//
//   1. CNTFRQ_EL0 (EL0-readable): generic timer frequency. QEMU's
//      default Cortex-A57 model reports 62.5 MHz (62_500_000). Real
//      ARMv8 silicon ships 19.2 MHz (Snapdragon family), 13 / 24 MHz
//      (MediaTek), 24 MHz (Exynos typical), 25 MHz, or 26 MHz. The
//      62.5 MHz value is so distinctively QEMU that it's a
//      single-signal verdict.
//
//   2. CTR_EL0 (EL0-readable): Cache Type Register. Recorded for
//      telemetry; we don't gate the verdict on it.
//
//   3. MIDR_EL1, REVIDR_EL1, ID_AA64ISAR0_EL1 (EL1, but the Linux
//      kernel emulates EL0 access via the MRS_EMULATION trap handler
//      enabled by default since Android 8). When emulation is
//      disabled by a custom kernel an MRS to these from EL0 raises
//      SIGILL; we wrap each read in a sigsetjmp/longjmp guard so the
//      SDK keeps working in degraded mode (CNTFRQ alone is still
//      enough for a verdict). These are recorded for telemetry only;
//      see the decision-rule note below.
//
// Decision rule:
//   decisive = (CNTFRQ == 62_500_000)
//
// Why CNTFRQ-only: an earlier revision of this probe also flipped
// `decisive` when REVIDR_EL1 == 0 AND MIDR_EL1's Implementer/PartNum
// matched QEMU's default (Implementer=0x41 ARM Ltd, PartNum in
// {0xD03 A53, 0xD05 A55, 0xD07 A57, 0xD08 A72}). That rule turns
// out to be a real-silicon false positive across most of the
// commodity ARM mobile-SoC market: MediaTek, UniSoC, Spreadtrum,
// AllWinner, Rockchip, etc. ship vanilla ARM reference cores under
// Implementer=0x41 (they don't customize MIDR), and most of them
// don't write a non-zero REVIDR either. Concrete observed false
// positive: a real Xiaomi/realme MT6877 device (Cortex-A55) reports
// midr=0x412fd050, revidr=0x0, cntfrq=13_000_000 — clearly real
// silicon, but the old rule fired on the (revidr_zero && midr_qemu)
// pair.
//
// The MIDR/REVIDR/ISAR0 values are still captured in `raw` so a
// maintainer can post-mortem reports without re-running the probe;
// they just don't influence `decisive` anymore.

#include "emu_probe.h"

#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

// Process-global trampoline for the SIGILL handler. The probe is
// single-threaded by construction (called once at SDK init from
// the runtime.emulator detector), so a global is fine.
sigjmp_buf g_mrs_trap;
volatile sig_atomic_t g_mrs_trapped = 0;

void mrs_sigill_handler(int /*sig*/, siginfo_t* /*info*/, void* /*ucontext*/) {
    g_mrs_trapped = 1;
    siglongjmp(g_mrs_trap, 1);
}

// Read [reg] (an MRS-syntax operand string) into [out]. Returns true
// on success, false if the kernel raised SIGILL (i.e. MRS_EMULATION
// is disabled or the register is genuinely inaccessible). On failure
// [out] is left untouched.
//
// Kept as a macro because the MRS operand must be a string literal —
// AArch64 GCC/Clang don't accept runtime register selection in
// `__asm__ volatile("mrs %0, %1", ...)`.
#define SAFE_MRS(out_var, reg_literal) ({                                    \
    bool _ok = false;                                                        \
    struct sigaction _old{};                                                 \
    struct sigaction _new{};                                                 \
    _new.sa_sigaction = mrs_sigill_handler;                                  \
    _new.sa_flags = SA_SIGINFO;                                              \
    sigemptyset(&_new.sa_mask);                                              \
    sigaction(SIGILL, &_new, &_old);                                         \
    g_mrs_trapped = 0;                                                       \
    if (sigsetjmp(g_mrs_trap, 1) == 0) {                                     \
        uint64_t _tmp = 0;                                                   \
        __asm__ volatile("mrs %0, " reg_literal : "=r"(_tmp));               \
        if (!g_mrs_trapped) {                                                \
            (out_var) = _tmp;                                                \
            _ok = true;                                                      \
        }                                                                    \
    }                                                                        \
    sigaction(SIGILL, &_old, nullptr);                                       \
    _ok;                                                                     \
})

// MIDR_EL1 layout: [31:24]=Implementer, [23:20]=Variant,
// [19:16]=Architecture (always 0xF on ARMv8), [15:4]=PartNum, [3:0]=Revision.
constexpr uint32_t midr_implementer(uint64_t midr) {
    return static_cast<uint32_t>((midr >> 24) & 0xFF);
}
constexpr uint32_t midr_partnum(uint64_t midr) {
    return static_cast<uint32_t>((midr >> 4) & 0xFFF);
}

// Implementer 0x41 (ARM Ltd) is what QEMU reports by default for its
// Cortex-A* models; combined with the specific PartNum it's a strong
// signal that we're in QEMU because real Snapdragon/Exynos/etc. ship
// under a different implementer (0x51 Qualcomm, 0x53 Samsung, etc.).
constexpr bool midr_matches_qemu_default(uint64_t midr) {
    if (midr_implementer(midr) != 0x41) return false;
    const uint32_t part = midr_partnum(midr);
    // PartNums QEMU's CPU-model table emits for its default cores.
    return part == 0xD03   // Cortex-A53
        || part == 0xD05   // Cortex-A55
        || part == 0xD07   // Cortex-A57
        || part == 0xD08;  // Cortex-A72
}

// Append [fmt...] to [buf] starting at [offset]; advance [offset]
// by however many bytes were written (clamped to capacity-1 to
// preserve the trailing NUL). Always leaves [buf] NUL-terminated.
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

}  // namespace

namespace dicore::emu {

Signals probe() {
    Signals s{};

    uint64_t cntfrq = 0;
    uint64_t ctr = 0;
    uint64_t midr = 0;
    uint64_t revidr = 0;
    uint64_t isar0 = 0;

    bool have_cntfrq = SAFE_MRS(cntfrq, "CNTFRQ_EL0");
    bool have_ctr    = SAFE_MRS(ctr,    "CTR_EL0");
    bool have_midr   = SAFE_MRS(midr,   "MIDR_EL1");
    bool have_revidr = SAFE_MRS(revidr, "REVIDR_EL1");
    bool have_isar0  = SAFE_MRS(isar0,  "ID_AA64ISAR0_EL1");

    bool cntfrq_qemu = have_cntfrq && cntfrq == 62'500'000ULL;
    // revidr_zero and midr_qemu are deliberately *not* gating the
    // verdict (see file-header decision-rule note). They're computed
    // here only so they can show up in `present` for telemetry, which
    // lets us see "CPU IDs look QEMU-shaped but CNTFRQ disagrees" on
    // real silicon vs. true emulators in the dashboard.
    bool revidr_zero = have_revidr && revidr == 0;
    bool midr_qemu = have_midr && midr_matches_qemu_default(midr);

    s.present = cntfrq_qemu || revidr_zero || midr_qemu;
    s.decisive = cntfrq_qemu;

    size_t off = 0;
    append_fmt(s.raw, sizeof(s.raw), &off, "arch=arm64");
    if (have_cntfrq) {
        append_fmt(s.raw, sizeof(s.raw), &off, "|cntfrq=%llu",
                   static_cast<unsigned long long>(cntfrq));
    } else {
        append_fmt(s.raw, sizeof(s.raw), &off, "|cntfrq=?");
    }
    if (have_ctr) {
        append_fmt(s.raw, sizeof(s.raw), &off, "|ctr=0x%llx",
                   static_cast<unsigned long long>(ctr));
    } else {
        append_fmt(s.raw, sizeof(s.raw), &off, "|ctr=?");
    }
    if (have_midr) {
        append_fmt(s.raw, sizeof(s.raw), &off, "|midr=0x%llx",
                   static_cast<unsigned long long>(midr));
    } else {
        append_fmt(s.raw, sizeof(s.raw), &off, "|midr=?");
    }
    if (have_revidr) {
        append_fmt(s.raw, sizeof(s.raw), &off, "|revidr=0x%llx",
                   static_cast<unsigned long long>(revidr));
    } else {
        append_fmt(s.raw, sizeof(s.raw), &off, "|revidr=?");
    }
    if (have_isar0) {
        append_fmt(s.raw, sizeof(s.raw), &off, "|isar0=0x%llx",
                   static_cast<unsigned long long>(isar0));
    } else {
        append_fmt(s.raw, sizeof(s.raw), &off, "|isar0=?");
    }

    return s;
}

}  // namespace dicore::emu
