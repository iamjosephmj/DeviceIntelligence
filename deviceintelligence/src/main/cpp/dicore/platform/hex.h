#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dicore::hex {

// Lowercase hex of [bytes, bytes+len) into a freshly-allocated std::string
// of length 2*len. Out-of-band-allocation-safe: if the allocation fails the
// caller will see an empty string (string ctors do not throw on Android's
// libc++ when malloc returns null only when -fno-exceptions; we accept the
// abort here, it's vanishingly rare for a 64-byte string).
std::string encode(const uint8_t* bytes, size_t len);

} // namespace dicore::hex
