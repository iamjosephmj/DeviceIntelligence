#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::crypto {

// AES-256-GCM (NIST SP 800-38D) with a 96-bit nonce. Self-owned.
// ct_out must have room for pt_len bytes; tag_out is 16 bytes.
bool aes256_gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* pt, size_t pt_len,
                     uint8_t* ct_out, uint8_t tag_out[16]);

// Verifies the tag in constant time BEFORE producing plaintext; returns false
// (and writes nothing to pt_out) on any tag mismatch — fail-closed.
// pt_out must have room for ct_len bytes.
bool aes256_gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len,
                     const uint8_t tag[16], uint8_t* pt_out);

} // namespace dicore::crypto
