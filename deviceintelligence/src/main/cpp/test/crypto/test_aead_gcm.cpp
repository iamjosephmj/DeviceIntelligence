// Host unit test (KAT) for AES-256 core + AES-256-GCM.
// FIPS-197 AES-256 block vector; McGrew GCM AES-256 test cases 15 (no AAD) and
// 16 (with AAD, partial blocks); a tamper (flipped-tag) fail case. Build cmd below.
#include "dicore/crypto/aead_gcm.h"
#include "dicore/crypto/aes_core.h"

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
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return v;
}
bool eqv(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}
} // namespace

int main() {
    using namespace dicore::crypto;

    // ---- FIPS-197 Appendix C.3 AES-256 single block ----
    {
        auto key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto in  = unhex("00112233445566778899aabbccddeeff");
        uint8_t rk[kAes256RoundKeyBytes], out[16];
        aes256_expand_key(key.data(), rk);
        aes256_encrypt_block(rk, in.data(), out);
        auto want = unhex("8ea2b7ca516745bfeafc49904b496089");
        assert(std::memcmp(out, want.data(), 16) == 0);
    }

    const auto key = unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const auto iv  = unhex("cafebabefacedbaddecaf888");

    // ---- McGrew GCM AES-256 Test Case 15 (no AAD) ----
    {
        auto pt = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        std::vector<uint8_t> ct(pt.size()); uint8_t tag[16];
        assert(aes256_gcm_seal(key.data(), iv.data(), nullptr, 0,
                               pt.data(), pt.size(), ct.data(), tag));
        auto want_ct = unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                             "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
        auto want_tag = unhex("b094dac5d93471bdec1a502270e3cc6c");
        assert(eqv(ct, want_ct));
        assert(std::memcmp(tag, want_tag.data(), 16) == 0);
        // round-trip open
        std::vector<uint8_t> rt(ct.size());
        assert(aes256_gcm_open(key.data(), iv.data(), nullptr, 0,
                               ct.data(), ct.size(), tag, rt.data()));
        assert(eqv(rt, pt));
    }

    // ---- McGrew GCM AES-256 Test Case 16 (AAD + partial blocks) ----
    {
        auto pt  = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        auto aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        std::vector<uint8_t> ct(pt.size()); uint8_t tag[16];
        assert(aes256_gcm_seal(key.data(), iv.data(), aad.data(), aad.size(),
                               pt.data(), pt.size(), ct.data(), tag));
        auto want_ct = unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                             "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        auto want_tag = unhex("76fc6ece0f4e1768cddf8853bb2d551b");
        assert(eqv(ct, want_ct));
        assert(std::memcmp(tag, want_tag.data(), 16) == 0);

        // Tamper: flip one tag byte -> open must fail-closed.
        uint8_t bad[16]; std::memcpy(bad, tag, 16); bad[0] ^= 0x01;
        std::vector<uint8_t> rt(ct.size(), 0xCC);
        assert(!aes256_gcm_open(key.data(), iv.data(), aad.data(), aad.size(),
                                ct.data(), ct.size(), bad, rt.data()));
        // Also flip a ciphertext byte -> open must fail.
        std::vector<uint8_t> ct2 = ct; ct2[0] ^= 0x01;
        assert(!aes256_gcm_open(key.data(), iv.data(), aad.data(), aad.size(),
                                ct2.data(), ct2.size(), tag, rt.data()));
    }

    std::printf("test_aead_gcm OK\n");
    return 0;
}

/* Build/run (host):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" "$CPP/dicore/crypto/test_aead_gcm.cpp" \
         "$CPP/dicore/crypto/aead_gcm.cpp" "$CPP/dicore/crypto/aes_core.cpp" \
         -o /tmp/test_aead_gcm && /tmp/test_aead_gcm */
