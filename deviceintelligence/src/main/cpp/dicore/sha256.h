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

// ---------------------------------------------------------------------------
// Incremental (streaming) SHA-256 API.
// Allows feeding data in arbitrarily-sized chunks; useful when the full input
// is not available in a contiguous buffer (e.g. inflate fixed-buffer loop).
// ---------------------------------------------------------------------------

struct Sha256Ctx {
    uint32_t state[8];   // running hash state
    uint64_t total_bits; // total message length in bits (updated on each call)
    uint8_t  buf[64];    // partial-block buffer
    size_t   buf_len;    // bytes currently buffered (0..63)
};

// Reset ctx to the SHA-256 initial state. Must be called before sha256_update.
void sha256_init  (Sha256Ctx* ctx);

// Feed len bytes of data into ctx. May be called any number of times.
void sha256_update(Sha256Ctx* ctx, const void* data, size_t len);

// Finalize the digest and write 32 bytes into out. ctx is unusable afterward.
void sha256_final (Sha256Ctx* ctx, uint8_t out[kDigestLen]);

} // namespace dicore::sha
