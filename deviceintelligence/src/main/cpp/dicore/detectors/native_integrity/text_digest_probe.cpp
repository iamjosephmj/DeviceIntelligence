// text_digest_probe.cpp — native_integrity probe for INTEL_0042
// (text_integrity_divergence). See text_digest.hpp for the verify contract;
// this TU locates our own executable segment and checks it against the
// build-time digest.
//
// BYTE-RANGE CONTRACT (must match tools/native/gen-dicore-text-digest.py):
// the build tool hashes the file bytes [p_offset, p_offset + p_filesz) of the
// FIRST PF_X PT_LOAD segment of libdicore.so; this probe hashes the same
// logical range at runtime — [dlpi_addr + p_vaddr, + p_filesz), located via
// dl_iterate_phdr (shared module_text.cpp helper, the technique G8/G10 use).
// The loader maps exactly those file bytes at that address and the exec
// segment carries no dynamic relocations, so the two ranges are byte-equal on
// an untampered build. The generated digest array lives in .rodata (a
// non-exec PT_LOAD), OUTSIDE the hashed range, so embedding it cannot change
// the digest.
//
// Reads go through safe_read_code (/proc/self/mem → process_vm_readv): our
// own .so is not built execute-only today, but G2's Android 10 XOM crash
// taught that assuming code memory is readable is the assumption that breaks.
// Any failure — no segment, unreadable bytes, no baseline — contributes
// nothing. Fail-open.

#include "dicore/core/verdict_cores.h"
#include "dicore/detectors/native_integrity/shared/module_text.h"
#include "dicore/detectors/native_integrity/text_digest.hpp"
#include "dicore/platform/obf.h"
#include "dicore/platform/safe_text_read.h"

// Build-generated (tools/native/gen-dicore-text-digest.py, run by CMake after
// the link): SHA-256 of the executable segment's file bytes. All-zero means
// "no baseline" — the first clean build generates the header only after the
// .so exists, so it embeds the zero seed; the next incremental build embeds
// the real digest. Treated below as skip, never as an expected value.
#include "dicore_text_digest_gen.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dicore {

namespace {

// True iff the baseline has at least one non-zero byte. An all-zero digest is
// the "not generated yet" sentinel, not a baseline — verifying against it
// would flag every untampered build. The read is VOLATILE deliberately: with
// a compile-time-visible array the optimizer would fold this check and strip
// the whole probe body when the zero seed is compiled in, making the
// executable-segment digest depend on whether the baseline had landed — the
// build would then oscillate instead of converging. Volatile keeps the
// compiled code byte-identical for any digest value, so the embedded digest
// is a fixed point after exactly one rebuild.
bool baseline_present(const uint8_t d[32]) {
    const volatile uint8_t* v = d;
    uint8_t any = 0;
    for (int i = 0; i < 32; ++i) any |= v[i];
    return any != 0;
}

}  // namespace

DI_OBF_ORCH
std::vector<std::string> text_digest_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    if (!baseline_present(DICORE_TEXT_DIGEST)) return {};

    native_integrity::LiveExecSeg seg;
    if (!native_integrity::find_live_exec_seg("libdicore.so", &seg)) return {};

    std::vector<uint8_t> bytes((size_t)seg.p_filesz);
    if (!platform::safe_read_code(reinterpret_cast<const void*>(seg.addr()),
                                   bytes.data(), bytes.size())) {
        return {};
    }

    if (dicore::text_digest::verify(bytes.data(), bytes.size(),
                                   DICORE_TEXT_DIGEST)) {
        return {};
    }

    const size_t pages = dicore::text_digest::count_mismatch_pages(
        bytes.data(), bytes.size(), DICORE_TEXT_DIGEST);

    // kind \x1f SEVERITY \x1f k=v|k=v...
    std::string r = "text_integrity_divergence";
    r += kFS;
    r += "CRITICAL";
    r += kFS;
    r += "segment_bytes=" + std::to_string(bytes.size());
    r += pages == SIZE_MAX ? "|mismatch_pages=unknown_v1"
                           : "|mismatch_pages=" + std::to_string(pages);
    out.push_back(r);
    return out;
}

}  // namespace dicore
