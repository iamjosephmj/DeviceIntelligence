// prologue_verify.cpp — native_integrity self-hook detector.
//
// G2 (text_verify) hashes the whole .text against the build-baked hash or a
// load-time snapshot. That catches an inline hook, but only when a build hash was
// baked OR the hook landed after our snapshot. This core closes the residual gap
// with a self-contained check: read the first instructions of a curated set of
// OUR OWN highest-value functions and flag the absolute-jump trampoline opcodes
// that inline-hooking engines (Dobby / Frida Gum / Substrate / *InlineHook)
// splice over a function entry. No baseline, no baked hash — so it fires even on
// a function hooked before JNI_OnLoad ran.
//
// Targets are the functions an attacker most wants to neuter or tap:
//   - the orchestrator entry (disable the whole sweep),
//   - the gated / env-KEK key derivations (tap the dex-string key),
//   - the watchdog kill request (turn the kill into a no-op).
//
// Detection is opcode-pattern based, NOT compare-to-baseline, so it is immune to
// per-build code drift and to the OLLVM flattening of the targets themselves: a
// legitimately-compiled prologue is stack setup (or a BTI landing pad), never an
// absolute-jump stub. Everything fails open; an unreadable address is skipped.

#include "dicore/platform/safe_text_read.h"
#include "dicore/jni/jni_anchors.h"
#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/core/verdict_cores.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dicore {
namespace {

// One scan target: a human label + the code address of one of our functions.
struct Target {
    const char* name;
    uintptr_t addr;
};

}  // namespace

// True if the bytes at `code` begin with a recognised inline-hook trampoline.
// Per-ABI; conservative — only unambiguous absolute/relative jump stubs match, so
// a real (even obfuscated) prologue does not. Exposed (verdict_cores.h) for tests.
bool prologue_looks_hooked(const uint8_t* code) {
#if defined(__aarch64__)
    uint32_t w0, w1;
    memcpy(&w0, code, 4);
    memcpy(&w1, code + 4, 4);
    // LDR x16/x17, #imm ; BR x16/x17  — load an absolute target, branch to it.
    // LDR Xt, literal = 0x58000000 | (imm19<<5) | Rt ; we match opcode + Rt∈{16,17}.
    bool ldr_x16_17 = (w0 & 0xFF00001Fu) == (0x58000000u | 16u) ||
                      (w0 & 0xFF00001Fu) == (0x58000000u | 17u);
    bool br_x16 = (w1 == 0xD61F0200u);  // BR x16
    bool br_x17 = (w1 == 0xD61F0220u);  // BR x17
    if (ldr_x16_17 && (br_x16 || br_x17)) return true;
    return false;
#elif defined(__x86_64__) || defined(__i386__)
    uint8_t b[12];
    memcpy(b, code, sizeof(b));
    if (b[0] == 0xE9) return true;                         // jmp rel32
    if (b[0] == 0xFF && b[1] == 0x25) return true;         // jmp [rip+disp32]
    if (b[0] == 0x68 && b[5] == 0xC3) return true;         // push imm32 ; ret
    if (b[0] == 0x48 && b[1] == 0xB8 &&                    // movabs rax, imm64 ;
        b[10] == 0xFF && b[11] == 0xE0) return true;       //   jmp rax
    return false;
#elif defined(__arm__)
    uint32_t w0;
    memcpy(&w0, code, 4);
    if (w0 == 0xE51FF004u) return true;                    // LDR pc, [pc, #-4]
    if (w0 == 0xE51FF000u) return true;                    // LDR pc, [pc]
    return false;
#else
    (void)code;
    return false;
#endif
}

DI_OBF_MAX
std::vector<std::string> prologue_verdict_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    const Target targets[] = {
        {"challenge",    reinterpret_cast<uintptr_t>(&anchors::nat_challenge)},
        {"enroll",       reinterpret_cast<uintptr_t>(&anchors::nat_enroll)},
        {"gated_key",    reinterpret_cast<uintptr_t>(&anchors::nat_gated_key)},
        {"registrar",    reinterpret_cast<uintptr_t>(&register_k_anchors)},
    };

    for (const Target& t : targets) {
        if (t.addr == 0) continue;
        // Via safe_read_code, not a raw deref: these are our OWN .text, which is
        // readable today, but the Android 10 execute-only crash proved that
        // assumption is not one to make about code memory. An unreadable target
        // yields no finding rather than a signal.
        uint8_t code[16];
        if (!platform::safe_read_code(reinterpret_cast<const void*>(t.addr),
                                      code, sizeof(code))) {
            continue;
        }
        if (prologue_looks_hooked(code)) {
            out.push_back(std::string("native_function_hooked") + kFS + "CRITICAL" + kFS +
                          "target=" + t.name);
        }
    }
    return out;
}

}  // namespace dicore
