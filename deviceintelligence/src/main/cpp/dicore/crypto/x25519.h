#pragma once

#include <cstdint>

namespace dicore::crypto {

// X25519 (RFC 7748) scalar multiplication. All buffers are 32 bytes.
// The scalar is clamped internally (RFC 7748 §5), so callers pass raw 32-byte
// secrets. Constant-time (Montgomery ladder + constant-time conditional swap).
//
// out = X25519(scalar, point).
void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

// out_pub = X25519(scalar, 9) — public key / base-point multiplication.
void x25519_base(uint8_t out_pub[32], const uint8_t scalar[32]);

} // namespace dicore::crypto
