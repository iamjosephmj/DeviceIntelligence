// Host unit test for dicore_token_encrypt (ECIES v2). Fixed server keypair + fixed
// ephemeral/nonce -> deterministic token; then reproduce the BACKEND decrypt
// (X25519(server_priv, eph_pub) -> HKDF -> AES-GCM-open) and assert round-trip.
// This mirrors exactly what the Kotlin :verifier will do (Task 7). Build below.
#include "dicore/crypto/token_crypto.h"
#include "dicore/crypto/aead_gcm.h"
#include "dicore/crypto/hkdf.h"
#include "dicore/crypto/x25519.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> v; v.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return v;
}
} // namespace

int main() {
    using namespace dicore::crypto;

    // Fixed server keypair.
    uint8_t server_priv[32];
    for (int i = 0; i < 32; ++i) server_priv[i] = static_cast<uint8_t>(i + 1);
    LicenceKey server;
    server.epoch = 3;
    x25519_base(server.pubkey, server_priv);

    // Fixed ephemeral + nonce.
    uint8_t eph_priv[32], nonce[12];
    for (int i = 0; i < 32; ++i) eph_priv[i] = static_cast<uint8_t>(0x80 ^ i);
    for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(0x10 + i);

    const std::string plain = "signed_content\n--BINDING\nSIG...\nCERT...";

    std::string token;
    assert(dicore_token_encrypt_with_ephemeral(plain, server, eph_priv, nonce, &token));

    // Structural checks.
    assert(token.size() > 2 && token[0] == '2' && token[1] == ':');
    auto payload = unhex(token.substr(2));
    // version(1)+epoch(1)+eph_pub(32)+nonce(12)+ct(plain.size())+tag(16)
    assert(payload.size() == 1 + 1 + 32 + 12 + plain.size() + 16);
    assert(payload[0] == 0x02);
    assert(payload[1] == 3);
    const uint8_t* eph_pub = payload.data() + 2;
    // eph_pub in the token must equal base(eph_priv).
    uint8_t want_pub[32]; x25519_base(want_pub, eph_priv);
    assert(std::memcmp(eph_pub, want_pub, 32) == 0);
    const uint8_t* tok_nonce = eph_pub + 32;
    assert(std::memcmp(tok_nonce, nonce, 12) == 0);
    const uint8_t* ct = tok_nonce + 12;
    size_t ct_len = plain.size();
    const uint8_t* tag = ct + ct_len;

    // ---- Reproduce the BACKEND decrypt ----
    uint8_t shared[32];
    x25519_scalarmult(shared, server_priv, eph_pub);           // server side ECDH
    // Derive the length from the literal — do NOT hardcode it. This was `info[12]`
    // with a memcpy of 11, which silently truncated when the prefix was renamed from
    // "intel-token-v2" (11 bytes) to "intel-token-v2" (14).
    static constexpr char kInfoPrefix[] = "intel-token-v2";
    static constexpr size_t kInfoPrefixLen = sizeof(kInfoPrefix) - 1;
    uint8_t info[kInfoPrefixLen + 1];
    std::memcpy(info, kInfoPrefix, kInfoPrefixLen);
    info[kInfoPrefixLen] = server.epoch;
    uint8_t key[32];
    assert(hkdf_sha256(shared, 32, tok_nonce, 12, info, sizeof(info), key, 32));
    uint8_t aad[34]; aad[0] = 0x02; aad[1] = server.epoch; std::memcpy(aad + 2, eph_pub, 32);
    std::vector<uint8_t> rt(ct_len);
    assert(aes256_gcm_open(key, tok_nonce, aad, sizeof(aad), ct, ct_len, tag, rt.data()));
    assert(rt.size() == plain.size() &&
           std::memcmp(rt.data(), plain.data(), plain.size()) == 0);

    // Tamper: flip a ciphertext byte -> backend open must fail.
    { std::vector<uint8_t> bad(ct, ct + ct_len); bad[0] ^= 0x01;
      std::vector<uint8_t> o(ct_len);
      assert(!aes256_gcm_open(key, tok_nonce, aad, sizeof(aad), bad.data(), ct_len, tag, o.data())); }

    // Determinism: same inputs -> identical token.
    std::string token2;
    assert(dicore_token_encrypt_with_ephemeral(plain, server, eph_priv, nonce, &token2));
    assert(token == token2);

    std::printf("test_token_crypto OK\n");
    return 0;
}

/* Build/run (host, with the android/log.h shim for sha256.cpp):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" -I<hostshim> \
       "$CPP/dicore/crypto/test_token_crypto.cpp" "$CPP/dicore/crypto/token_crypto.cpp" \
       "$CPP/dicore/crypto/x25519.cpp" "$CPP/dicore/crypto/hkdf.cpp" \
       "$CPP/dicore/crypto/aead_gcm.cpp" "$CPP/dicore/crypto/aes_core.cpp" \
       "$CPP/dicore/crypto/rand.cpp" "$CPP/dicore/crypto/sha256.cpp" \
       -o /tmp/test_token_crypto && /tmp/test_token_crypto */
