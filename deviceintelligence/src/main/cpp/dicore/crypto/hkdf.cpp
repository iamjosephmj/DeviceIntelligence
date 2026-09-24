#include "dicore/crypto/hkdf.h"

#include "dicore/crypto/sha256.h"

#include <cstring>
#include <vector>

namespace dicore::crypto {
namespace {
constexpr size_t kBlock  = 64;  // SHA-256 block size
constexpr size_t kDigest = 32;  // SHA-256 output size

// Zero secret-bearing scratch before it goes out of scope. volatile so the
// store is an observable side effect the optimizer may not elide.
void wipe(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}
} // namespace

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[32]) {
    // Normalize the key to a single block: hash it if longer, else zero-pad.
    uint8_t k[kBlock];
    std::memset(k, 0, kBlock);
    if (key_len > kBlock) {
        dicore::sha::sha256(key, key_len, k);   // first 32 bytes set, rest stay 0
    } else if (key_len > 0) {
        std::memcpy(k, key, key_len);
    }

    uint8_t ipad[kBlock], opad[kBlock];
    for (size_t i = 0; i < kBlock; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }

    // inner = SHA256(ipad || msg)
    std::vector<uint8_t> inner;
    inner.reserve(kBlock + msg_len);
    inner.insert(inner.end(), ipad, ipad + kBlock);
    if (msg_len > 0 && msg != nullptr) inner.insert(inner.end(), msg, msg + msg_len);
    uint8_t inner_hash[kDigest];
    dicore::sha::sha256(inner.data(), inner.size(), inner_hash);

    // out = SHA256(opad || inner_hash)
    uint8_t outer[kBlock + kDigest];
    std::memcpy(outer, opad, kBlock);
    std::memcpy(outer + kBlock, inner_hash, kDigest);
    dicore::sha::sha256(outer, sizeof(outer), out);

    // The key-derived pads and the (secret) message copy in `inner` are all
    // sensitive when this HMAC keys HKDF on the ECDH secret / PRK — wipe them.
    wipe(k, sizeof(k));
    wipe(ipad, sizeof(ipad));
    wipe(opad, sizeof(opad));
    wipe(inner_hash, sizeof(inner_hash));
    wipe(outer, sizeof(outer));
    if (!inner.empty()) wipe(inner.data(), inner.size());
}

bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    if (out_len > 255u * kDigest) return false;

    // Extract: PRK = HMAC(salt, IKM). Empty salt -> a block of zeros (RFC 5869 §2.2).
    uint8_t prk[kDigest];
    if (salt != nullptr && salt_len > 0) {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    } else {
        uint8_t zero_salt[kDigest];
        std::memset(zero_salt, 0, kDigest);
        hmac_sha256(zero_salt, kDigest, ikm, ikm_len, prk);
    }

    // Expand: T(i) = HMAC(PRK, T(i-1) || info || i), OKM = T(1) || T(2) || ...
    uint8_t t[kDigest];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 0;
    while (done < out_len) {
        ++counter;                              // 1..255; bounded by the out_len check above
        std::vector<uint8_t> block_in;
        block_in.reserve(t_len + info_len + 1);
        if (t_len > 0) block_in.insert(block_in.end(), t, t + t_len);
        if (info != nullptr && info_len > 0) block_in.insert(block_in.end(), info, info + info_len);
        block_in.push_back(counter);
        hmac_sha256(prk, kDigest, block_in.data(), block_in.size(), t);
        t_len = kDigest;

        const size_t take = (out_len - done < kDigest) ? (out_len - done) : kDigest;
        std::memcpy(out + done, t, take);
        done += take;
        if (!block_in.empty()) wipe(block_in.data(), block_in.size());   // holds T(i-1)
    }
    // PRK and the last T block are as sensitive as the derived key material.
    wipe(prk, sizeof(prk));
    wipe(t, sizeof(t));
    return true;
}

} // namespace dicore::crypto
