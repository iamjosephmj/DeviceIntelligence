#pragma once

#include <cstddef>

// Raw DEFLATE decompression — a thin in-house facade over the vendored inflater
// so callers don't reference the underlying engine directly.
namespace dicore::crypto {

// Inflate [in]/[in_len] raw-DEFLATE bytes into a freshly allocated buffer
// (release with free()); *out_len receives the size. Returns nullptr on failure.
void* inflate_deflate(const void* in, size_t in_len, size_t* out_len);

}  // namespace dicore::crypto
