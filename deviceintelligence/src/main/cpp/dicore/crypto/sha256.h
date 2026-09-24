#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::sha {

constexpr size_t kDigestLen = 32;

// Initialize the SHA backend by dlopen'ing the system BoringSSL.
// Idempotent. Returns true on success, false if libcrypto.so is unavailable
// or doesn't export the symbols we need (which on Android effectively
// never happens, but we surface the failure rather than crash).
bool ensure_initialized();

// Compute SHA-256 over [data, data+len). Writes 32 bytes into out.
// Returns false if the backend failed to initialize. Thread-safe.
bool sha256(const void* data, size_t len, uint8_t out[kDigestLen]);

} // namespace dicore::sha
