#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::crypto {

// HMAC-SHA256 (RFC 2104 / FIPS 198-1). Writes 32 bytes to out.
// key/msg may be null when their length is 0.
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[32]);

// HKDF-SHA256 (RFC 5869): Extract-then-Expand. Derives out_len bytes into out.
// salt/info may be null (treated as empty). Returns false if out_len > 255*32
// (the HKDF maximum) — callers must check. Self-contained: builds on the
// vendored dicore::sha::sha256 (no OS crypto — dlopen of libcrypto no-ops on
// Android, see sha256.cpp).
bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

} // namespace dicore::crypto
