// See trampoline.h.
#include "dicore/platform/log.h"
#include "dicore/core/verdict_cores.h"
#include "dicore/orchestrator/record_util.h"
#include "dicore/detectors/environment/maps/maps_parse.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <unistd.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <link.h>
#include "dicore/detectors/environment/maps/module_enrich.h"

namespace dicore {
namespace env {

std::string trampoline_target(uintptr_t alo, uintptr_t ahi,
                              const std::vector<std::pair<uintptr_t,uintptr_t>>& fr,
                              const std::vector<std::string>& fmod,
                              bool* out_found) {
    static uintptr_t tb[1024];
    uintptr_t scan_hi = (ahi - alo > (64u << 10)) ? alo + (64u << 10) : ahi;  // cap 64KB
    for (uintptr_t off = alo; off < scan_hi; off += sizeof(tb)) {
        size_t want = std::min((size_t)(scan_hi - off), sizeof(tb));
        struct iovec lo{tb, want};
        struct iovec ro{reinterpret_cast<void*>(off), want};
        ssize_t n = process_vm_readv(getpid(), &lo, 1, &ro, 1, 0);
        if (n <= 0) continue;
        for (size_t k = 0; k * sizeof(uintptr_t) < (size_t)n; ++k) {
            uintptr_t w = tb[k];
            for (size_t fi = 0; fi < fr.size(); ++fi)
                if (w >= fr[fi].first && w < fr[fi].second) {
                    // Provenance is CONFIRMED here regardless of whether we can NAME the
                    // module: module_id_from_path() only yields an id for
                    // /data/adb/modules/<id>/… paths, so a hook injected from anywhere else
                    // (app data dir, /data/local/tmp, a dlopen'd payload) returns "".
                    // Report the find separately from the name so the caller does not treat
                    // an unnamed-but-foreign target as "nothing found".
                    if (out_found) *out_found = true;
                    return fmod[fi];
                }
        }
    }
    return "";
}

// Signal D helper: decode the branch target of an inline-hook prologue at [addr].
// Per-ABI, and deliberately mirrors the shapes prologue_looks_hooked() recognises
// (INTEL_0039) so the provenance check (INTEL_0038) can attribute every stub the shape
// check can see. Returns 0 if the prologue is not a branch (the normal case).
// All reads are bounded via pvr (EFAULT, never a fault).
//
// Previously ARM64-only, which left INTEL_0038 structurally unable to fire on
// x86_64/x86 (emulators — so red-team runs there silently "passed" it) and on
// armeabi-v7a, a shipped ABI.
uintptr_t prologue_branch_target(uintptr_t addr) {
#if defined(__aarch64__)
    uint32_t w0 = 0, w1 = 0;
    if (!pvr(addr, &w0)) return 0;
    if ((w0 & 0xFC000000u) == 0x14000000u) {            // B imm26
        int32_t imm = (int32_t)(w0 & 0x03FFFFFFu);
        if (imm & 0x02000000) imm |= (int32_t)0xFC000000u;   // sign-extend 26 bits
        return addr + ((intptr_t)imm << 2);
    }
    if (!pvr(addr + 4, &w1)) return 0;
    bool ldr16 = (w0 & 0xFF00001Fu) == (0x58000000u | 16u);
    bool ldr17 = (w0 & 0xFF00001Fu) == (0x58000000u | 17u);
    if ((ldr16 && w1 == 0xD61F0200u) || (ldr17 && w1 == 0xD61F0220u)) {
        uint64_t tgt = 0;
        if (pvr(addr + 8, &tgt)) return (uintptr_t)tgt;
    }
    return 0;
#elif defined(__x86_64__) || defined(__i386__)
    uint8_t b[12];
    if (!pvr(addr, &b)) return 0;
    if (b[0] == 0xE9) {                                  // jmp rel32
        int32_t rel = 0; std::memcpy(&rel, b + 1, 4);
        return addr + 5 + (intptr_t)rel;                 // rel is from the NEXT instruction
    }
    if (b[0] == 0xFF && b[1] == 0x25) {                  // jmp [rip+disp32] (x86_64)
        int32_t disp = 0; std::memcpy(&disp, b + 2, 4);
#if defined(__x86_64__)
        uintptr_t slot = addr + 6 + (intptr_t)disp;      // RIP-relative
#else
        uintptr_t slot = (uintptr_t)(uint32_t)disp;      // i386: absolute [disp32]
#endif
        uintptr_t tgt = 0;
        if (pvr(slot, &tgt)) return tgt;                 // one deref: the pointer slot
        return 0;
    }
    if (b[0] == 0x68 && b[5] == 0xC3) {                  // push imm32 ; ret
        uint32_t imm = 0; std::memcpy(&imm, b + 1, 4);
        return (uintptr_t)imm;
    }
    if (b[0] == 0x48 && b[1] == 0xB8 &&                  // movabs rax, imm64 ; jmp rax
        b[10] == 0xFF && b[11] == 0xE0) {
        uint64_t imm = 0; std::memcpy(&imm, b + 2, 8);
        return (uintptr_t)imm;
    }
    return 0;
#elif defined(__arm__)
    uint32_t w0 = 0;
    if (!pvr(addr, &w0)) return 0;
    if (w0 == 0xE51FF004u) {                             // LDR pc, [pc, #-4]
        uint32_t tgt = 0;
        if (pvr(addr + 4, &tgt)) return (uintptr_t)tgt;
    }
    return 0;
#else
    (void)addr;
    return 0;
#endif
}

// INTEL_0039 attribution: follow the trampoline's BRANCH chain from `start` (up to 8 hops,
// decoding B / BL / LDR x16|x17+BR) and return the first module whose FOREIGN code range a
// hop lands in — recovering the culprit the level-1 pointer-scan missed (relative branches
// store no pointer; multi-stage trampolines hide the module past the first page). Also
// classifies the trampoline shape from the entry instruction (out_class). Pure enrichment
// on an already-confirmed hook, so no FP surface. Bounded pvr reads; visited-guarded.
std::string trampoline_follow(uintptr_t start,
                              const std::vector<std::pair<uintptr_t,uintptr_t>>& fr,
                              const std::vector<std::string>& fmod,
                              std::string* out_class) {
    uintptr_t pc = start;
    uintptr_t seen[8] = {0};
    for (int hop = 0; hop < 8; ++hop) {
        for (int i = 0; i < hop; ++i) if (seen[i] == pc) return "";   // loop guard
        seen[hop] = pc;
        for (size_t fi = 0; fi < fr.size(); ++fi)
            if (pc >= fr[fi].first && pc < fr[fi].second) return fmod[fi];   // reached a foreign module
        uint32_t w0 = 0, w1 = 0;
        if (!pvr(pc, &w0)) break;
        if (hop == 0 && out_class) {
            if ((w0 & 0xFF00001Fu) == (0x58000000u | 16u) || (w0 & 0xFF00001Fu) == (0x58000000u | 17u))
                *out_class = "abs_ptr";       // LDR xN,lit ; BR xN  (Dobby/ShadowHook far-jump class)
            else if ((w0 & 0x7C000000u) == 0x14000000u)
                *out_class = "pc_rel";        // B / BL          (near-jump class)
            else
                *out_class = "inline_code";   // handler body spliced in place
        }
        // B (0x14......) or BL (0x94......): pc-relative, imm26<<2.
        if ((w0 & 0x7C000000u) == 0x14000000u) {
            int32_t imm = (int32_t)(w0 & 0x03FFFFFFu);
            if (imm & 0x02000000) imm |= (int32_t)0xFC000000u;
            pc = pc + ((intptr_t)imm << 2);
            continue;
        }
        // LDR x16/x17, literal ; BR x16/x17: load an absolute target and branch to it.
        bool ldr16 = (w0 & 0xFF00001Fu) == (0x58000000u | 16u);
        bool ldr17 = (w0 & 0xFF00001Fu) == (0x58000000u | 17u);
        if ((ldr16 || ldr17) && pvr(pc + 4, &w1) &&
            ((ldr16 && w1 == 0xD61F0200u) || (ldr17 && w1 == 0xD61F0220u))) {
            int32_t imm19 = (int32_t)((w0 >> 5) & 0x7FFFFu);
            if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000u;   // sign-extend 19 bits
            uintptr_t lit = pc + ((intptr_t)imm19 << 2);
            uint64_t ptr = 0;
            if (!pvr(lit, &ptr)) break;
            pc = (uintptr_t)ptr;
            continue;
        }
        break;   // not a recognised branch -> handler body; stop
    }
    return "";
}


}  // namespace env
}  // namespace dicore
