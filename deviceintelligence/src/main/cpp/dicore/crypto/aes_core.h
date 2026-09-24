#pragma once

#include <cstdint>

namespace dicore::crypto {

// AES-256 (FIPS-197) encryption core — encrypt-only (GCM never needs decrypt).
// Self-owned/vendored; no OS crypto (dlopen of libcrypto no-ops on Android).
// NOTE: uses a byte S-box (T-table-free). This removes the large-table cache
// footprint but the 256-byte S-box is not fully constant-time; for the v2-token
// use (per-token ephemeral keys, device encrypting its own data) that residual
// timing leak is acceptable. A bitsliced constant-time core is a documented
// hardening follow-up.

constexpr int kAes256RoundKeyBytes = 240;  // 4 * (Nr+1) words, Nr=14

// Expand a 32-byte key into round keys (240 bytes).
void aes256_expand_key(const uint8_t key[32], uint8_t round_keys[kAes256RoundKeyBytes]);

// Encrypt one 16-byte block in place-free form: out = AES-256(round_keys, in).
void aes256_encrypt_block(const uint8_t round_keys[kAes256RoundKeyBytes],
                          const uint8_t in[16], uint8_t out[16]);

} // namespace dicore::crypto
