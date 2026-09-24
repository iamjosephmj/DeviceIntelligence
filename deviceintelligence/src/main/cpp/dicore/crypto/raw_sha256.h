#pragma once

// Self-contained SHA-256 (FIPS 180-4) — no backend, no dlopen, no state.
//
// dicore::sha::sha256 (crypto/sha256.h) is BoringSSL-backed: it dlopens
// libcrypto on first use, which makes it unusable from init_array constructors
// (loader locks held) and hands the digest to any process-wide libcrypto hook.
// The digest-bound string keys (plan task A1) need SHA-256 in exactly that
// hostile spot — the strenc ctor, before any Java code runs — so this variant
// computes the digest inline. KAT-pinned against the same FIPS vectors in
// test/platform/test_own_image.cpp; python-hashlib agreement is pinned by the
// obf-check bind/tamper legs (the POST_BUILD tool hashes the same bytes with
// hashlib).

#include <cstddef>
#include <cstdint>

namespace dicore::sha {

// SHA-256 over [data, data+len). Writes 32 bytes into out. Cannot fail.
void raw_sha256(const void* data, size_t len, uint8_t out[32]);

} // namespace dicore::sha
