#include "dicore/crypto/licence_blob.h"

#include "dicore/crypto/hkdf.h"
#include "dicore/crypto/sha256.h"

#include <cstring>

namespace dicore::crypto {

namespace {
constexpr size_t kBodyLen = 40;    // RVN1: magic..pubkey
constexpr size_t kFileLen = 72;    // RVN1: body + 32-byte checksum
constexpr size_t kBody2Len = 80;   // RVN2: magic..not_after (the signed region)
constexpr size_t kFile2Len = 144;  // RVN2: body + 64-byte signature
constexpr size_t kTagLen = 32;     // HMAC-SHA256 output; sig[32..63] reserved

// Publisher signing key. Obfuscated at build time along with the rest of the core;
// symmetric and therefore extractable by anyone willing to pull the binary apart,
// which is acceptable only because the check it guards is a fail-fast (see licence_blob.h).
alignas(8) const uint8_t kPublisherKey[32] = {
    0x8f, 0x2c, 0x1b, 0xa9, 0x40, 0xe7, 0xd3, 0x5c,
    0x6a, 0x1f, 0x0b, 0x8e, 0x2d, 0x4c, 0x9a, 0x37,
    0xb5, 0x63, 0xe0, 0x11, 0x7a, 0xc8, 0x94, 0x2f,
    0x0d, 0x56, 0xab, 0x38, 0xe4, 0x71, 0x9c, 0x60,
};

// Constant-time equality: never short-circuit on a secret comparison.
inline bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

bool parse_v1(const uint8_t* buf, LicenceKey* out) {
    if (buf[4] != 0x01) return false;                    // version
    if (buf[6] != 0x01) return false;                    // curve = X25519
    // buf[5] = epoch, buf[7] = reserved (not validated)

    uint8_t sum[32];
    if (!dicore::sha::sha256(buf, kBodyLen, sum)) return false;
    if (!constant_time_eq(sum, buf + kBodyLen, 32)) return false;

    out->epoch = buf[5];
    std::memcpy(out->pubkey, buf + 8, 32);
    std::memset(out->pkg_hash, 0, 32);                   // RVN1 carries no binding
    out->not_after = 0;                                  // and no expiry
    return true;
}

bool parse_v2(const uint8_t* buf, LicenceKey* out) {
    if (buf[4] != 0x02) return false;                    // version
    if (buf[6] != 0x01) return false;                    // curve = X25519

    // sig[32..63] is reserved for a future asymmetric scheme. A non-zero tail is a
    // version this build does not understand, so refuse rather than ignore it.
    for (size_t i = kTagLen; i < 64; ++i) {
        if (buf[kBody2Len + i] != 0x00) return false;
    }

    uint8_t tag[32];
    hmac_sha256(kPublisherKey, sizeof(kPublisherKey), buf, kBody2Len, tag);
    if (!constant_time_eq(tag, buf + kBody2Len, kTagLen)) return false;

    out->epoch = buf[5];
    std::memcpy(out->pubkey, buf + 8, 32);
    std::memcpy(out->pkg_hash, buf + 40, 32);
    uint64_t na = 0;
    for (int i = 0; i < 8; ++i) na = (na << 8) | static_cast<uint64_t>(buf[72 + i]);
    out->not_after = na;
    return true;
}
} // namespace

bool licence_blob_parse(const uint8_t* buf, size_t len, LicenceKey* out) {
    if (buf == nullptr || out == nullptr) return false;
    if (len == kFile2Len && std::memcmp(buf, "RVN2", 4) == 0) return parse_v2(buf, out);
    if (len == kFileLen && std::memcmp(buf, "RVN1", 4) == 0) return parse_v1(buf, out);
    return false;
}

void licence_blob_sign_for_test(const uint8_t* body80, uint8_t* out64) {
    hmac_sha256(kPublisherKey, sizeof(kPublisherKey), body80, kBody2Len, out64);
    std::memset(out64 + kTagLen, 0, 64 - kTagLen);
}

} // namespace dicore::crypto
