#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::crypto {

// Fill [out, out+len) with cryptographically secure random bytes.
// getrandom(2) (blocking on the pool being ready), falling back to /dev/urandom.
// Returns false only if both sources fail.
bool secure_random(uint8_t* out, size_t len);

} // namespace dicore::crypto
