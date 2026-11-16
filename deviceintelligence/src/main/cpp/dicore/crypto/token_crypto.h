#pragma once

#include "dicore/crypto/licence_blob.h"

#include <cstdint>
#include <string>

namespace dicore::crypto {

// ECIES v2 token encrypt (see docs/specs/2026-08-22-hybrid-encrypt-token-design.md).
// Ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM to the pinned server public key.
// Output: "2:" + hex(version(1)||epoch(1)||eph_pub(32)||nonce(12)||ciphertext||tag(16)).
// Fail-closed: returns false on any RNG/crypto error (caller must NOT emit a v1
// fallback in a v2 build). The ephemeral private key, shared secret, and AEAD key
// are wiped before return.
bool dicore_token_encrypt(const std::string& plain, const LicenceKey& server, std::string* out_v2);

// Test seam: same as above but with a caller-supplied ephemeral private key and
// nonce, so the construction is deterministic under KAT. Production code uses the
// public entry point (which sources both from secure_random).
bool dicore_token_encrypt_with_ephemeral(const std::string& plain, const LicenceKey& server,
                                     const uint8_t eph_priv[32], const uint8_t nonce[12],
                                     std::string* out_v2);

} // namespace dicore::crypto
