#include "sha256.h"

#include "log.h"

#include <cstring>

namespace dicore::sha {

// Self-contained FIPS 180-4 SHA-256.
//
// Originally we tried dlopen("libcrypto.so") for the boringssl SHA256 entry
// point, but Android's linker namespace isolation (API 28+) prevents app
// processes from resolving system /system/lib64/libcrypto.so symbols, so
// that path silently no-ops on real devices. A vendored implementation is
// the only path that works without requiring the NDK to ship a public
// crypto ABI (which it does not).

namespace {

constexpr uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr uint32_t H0[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t big32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

void compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = big32(block + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t T1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t T2 = S0 + mj;
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

} // namespace

bool ensure_initialized() {
    // No external dependency; always ready.
    return true;
}

// ---------------------------------------------------------------------------
// Incremental SHA-256 implementation
// ---------------------------------------------------------------------------

void sha256_init(Sha256Ctx* ctx) {
    std::memcpy(ctx->state, H0, sizeof(H0));
    ctx->total_bits = 0;
    ctx->buf_len    = 0;
}

void sha256_update(Sha256Ctx* ctx, const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    ctx->total_bits += static_cast<uint64_t>(len) * 8u;

    // If there's a partial block buffered, top it up first.
    if (ctx->buf_len > 0) {
        size_t need = 64 - ctx->buf_len;
        size_t take = (len < need) ? len : need;
        std::memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p   += take;
        len -= take;
        if (ctx->buf_len == 64) {
            compress(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }

    // Process full blocks directly from the caller's buffer.
    while (len >= 64) {
        compress(ctx->state, p);
        p   += 64;
        len -= 64;
    }

    // Buffer the remainder (0..63 bytes).
    if (len > 0) {
        std::memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

void sha256_final(Sha256Ctx* ctx, uint8_t out[kDigestLen]) {
    // Build and compress the padding block(s).
    uint8_t tail[128];
    std::memset(tail, 0, sizeof(tail));
    if (ctx->buf_len > 0) {
        std::memcpy(tail, ctx->buf, ctx->buf_len);
    }
    tail[ctx->buf_len] = 0x80;

    size_t pad_end = (ctx->buf_len < 56) ? 64 : 128;
    uint64_t bit_len = ctx->total_bits;
    for (int i = 0; i < 8; ++i) {
        tail[pad_end - 1 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
    }

    compress(ctx->state, tail);
    if (pad_end == 128) compress(ctx->state, tail + 64);

    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>(ctx->state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i]);
    }
}

// ---------------------------------------------------------------------------
// One-shot convenience — routed through the incremental API so behavior is
// identical by construction.
// ---------------------------------------------------------------------------

bool sha256(const void* data, size_t len, uint8_t out[kDigestLen]) {
    Sha256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
    return true;
}

} // namespace dicore::sha
