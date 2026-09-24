#include "dicore/crypto/token_crypto.h"

#include "dicore/crypto/aead_gcm.h"
#include "dicore/crypto/hkdf.h"
#include "dicore/crypto/rand.h"
#include "dicore/crypto/x25519.h"

#include <cstring>
#include <vector>

namespace dicore::crypto {
namespace {

constexpr uint8_t kVersion = 0x02;
const char kInfoPrefix[] = "intel-token-v2";          // length via sizeof-1, no NUL
constexpr size_t kInfoPrefixLen = sizeof(kInfoPrefix) - 1;

void secure_wipe(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

void hex_append(std::string* s, const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        s->push_back(d[p[i] >> 4]);
        s->push_back(d[p[i] & 0x0f]);
    }
}

} // namespace

bool dicore_token_encrypt_with_ephemeral(const std::string& plain, const LicenceKey& server,
                                     const uint8_t eph_priv[32], const uint8_t nonce[12],
                                     std::string* out_v2) {
    if (out_v2 == nullptr) return false;

    uint8_t eph_pub[32];
    x25519_base(eph_pub, eph_priv);

    uint8_t shared[32];
    x25519_scalarmult(shared, eph_priv, server.pubkey);

    // Reject a degenerate (all-zero) shared secret — the result of a low-order
    // server point (RFC 7748 §6.1). Defends against a swapped server pubkey that
    // would force a predictable key. Constant-time OR over all bytes.
    uint8_t nz = 0;
    for (int i = 0; i < 32; ++i) nz |= shared[i];
    if (nz == 0) { secure_wipe(shared, sizeof(shared)); return false; }

    // key = HKDF(ikm=shared, salt=nonce, info="intel-token-v2"||epoch, 32)
    uint8_t info[kInfoPrefixLen + 1];
    std::memcpy(info, kInfoPrefix, kInfoPrefixLen);
    info[kInfoPrefixLen] = server.epoch;
    uint8_t key[32];
    bool ok = hkdf_sha256(shared, sizeof(shared), nonce, 12, info, sizeof(info), key, sizeof(key));

    // aad = version || epoch || eph_pub
    uint8_t aad[1 + 1 + 32];
    aad[0] = kVersion;
    aad[1] = server.epoch;
    std::memcpy(aad + 2, eph_pub, 32);

    std::vector<uint8_t> ct(plain.size());
    uint8_t tag[16];
    if (ok) {
        ok = aes256_gcm_seal(key, nonce, aad, sizeof(aad),
                             reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
                             ct.data(), tag);
    }

    // Wipe secrets regardless of outcome.
    secure_wipe(shared, sizeof(shared));
    secure_wipe(key, sizeof(key));
    if (!ok) return false;

    // payload = version || epoch || eph_pub || nonce || ct || tag
    std::string hex;
    hex.reserve(2 + 2 * (1 + 1 + 32 + 12 + ct.size() + 16));
    hex.push_back('2');
    hex.push_back(':');
    uint8_t hdr[2] = {kVersion, server.epoch};
    hex_append(&hex, hdr, 2);
    hex_append(&hex, eph_pub, 32);
    hex_append(&hex, nonce, 12);
    if (!ct.empty()) hex_append(&hex, ct.data(), ct.size());
    hex_append(&hex, tag, 16);
    *out_v2 = std::move(hex);
    return true;
}

bool dicore_token_encrypt(const std::string& plain, const LicenceKey& server, std::string* out_v2) {
    uint8_t eph_priv[32], nonce[12];
    if (!secure_random(eph_priv, sizeof(eph_priv))) { secure_wipe(eph_priv, sizeof(eph_priv)); return false; }
    if (!secure_random(nonce, sizeof(nonce))) { secure_wipe(eph_priv, sizeof(eph_priv)); return false; }
    bool ok = dicore_token_encrypt_with_ephemeral(plain, server, eph_priv, nonce, out_v2);
    secure_wipe(eph_priv, sizeof(eph_priv));
    return ok;
}

} // namespace dicore::crypto
