#include "dicore/crypto/siphash.h"

#include <cstring>

namespace dicore::crypto {

namespace {
inline uint64_t rotl(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }
}  // namespace

uint64_t siphash24(const uint8_t* in, size_t len, uint64_t k0, uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    auto round = [&]() {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    };
    const size_t end = len - (len % 8);
    uint64_t b = static_cast<uint64_t>(len) << 56;
    for (size_t i = 0; i < end; i += 8) {
        uint64_t m; memcpy(&m, in + i, 8);
        v3 ^= m; round(); round(); v0 ^= m;
    }
    uint64_t last = 0; memcpy(&last, in + end, len - end);
    b |= last;
    v3 ^= b; round(); round(); v0 ^= b;
    v2 ^= 0xff; round(); round(); round(); round();
    return v0 ^ v1 ^ v2 ^ v3;
}

}  // namespace dicore::crypto
