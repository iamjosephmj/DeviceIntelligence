// text_digest.hpp — INTEL_0059 .text section digest verifier.
// Computes/verifies a SHA-256 over a native .text region (whole-buffer
// digest). `count_mismatch_pages` keeps a page-walk signature for the
// future obfuscator pass: v1 verifies the whole-region digest only and
// reports "mismatch, no page detail" (SIZE_MAX) rather than per-page
// counts, so callers are written against the final shape today.
#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::text_digest {

// SHA-256 over [bytes, bytes+len). Writes 32 bytes into out. If the crypto
// backend fails to initialize, out is zeroed (verify against any real
// expected digest then fails closed).
void compute(const void* bytes, size_t len, uint8_t out[32]);

// Computes the digest of [bytes, bytes+len) and compares it against
// `expected` in constant time (XOR-fold, same helper style as the
// INTEL_0058 channel guard).
bool verify(const void* bytes, size_t len, const uint8_t expected[32]);

// Whole-region digest first: match => 0 (fast path). On mismatch v1 has no
// build-time per-page table, so it reports SIZE_MAX ("mismatch, no page
// detail"); the 4 KiB page walk + per-page digests arrive with the
// obfuscator pass. Signature is stable — do not change it then.
size_t count_mismatch_pages(const void* text_begin, size_t text_len,
                            const uint8_t full_digest[32]);

} // namespace dicore::text_digest
