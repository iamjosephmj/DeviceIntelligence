// text_digest.cpp — INTEL_0059 .text section digest verifier.
// Thin wrapper over the vendored SHA-256 (dicore::sha) — the same
// backend every other crypto TU uses — plus a constant-time 32-byte
// compare copied from the INTEL_0058 channel guard. Pure host-testable
// logic; no JNI, no platform calls.
#include "dicore/detectors/native_integrity/text_digest.hpp"

#include "dicore/crypto/sha256.h"

#include <cstring>

namespace dicore::text_digest {
namespace {

// Constant-time 32-byte compare: XOR-fold, result == 0 means equal.
bool ct_eq_32(const uint8_t* a, const uint8_t* b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

} // namespace

void compute(const void* bytes, size_t len, uint8_t out[32]) {
    if (!dicore::sha::sha256(bytes, len, out)) {
        std::memset(out, 0, 32);  // fail closed: never leave stale bytes
    }
}

bool verify(const void* bytes, size_t len, const uint8_t expected[32]) {
    uint8_t actual[32];
    compute(bytes, len, actual);
    return ct_eq_32(actual, expected);
}

size_t count_mismatch_pages(const void* text_begin, size_t text_len,
                            const uint8_t full_digest[32]) {
    // Fast path: whole-region digest intact => no mismatched pages.
    if (verify(text_begin, text_len, full_digest)) {
        return 0;
    }
    // v1: no build-time per-page table exists yet, so we cannot attribute
    // the mismatch to specific 4 KiB pages. SIZE_MAX encodes "mismatch,
    // no page detail"; the obfuscator pass adds the per-page walk behind
    // this same signature.
    return SIZE_MAX;
}

} // namespace dicore::text_digest
