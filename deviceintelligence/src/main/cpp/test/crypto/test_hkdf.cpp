// Host unit test (KAT) for HMAC-SHA256 + HKDF-SHA256.
// RFC 4231 (HMAC-SHA256) + RFC 5869 (HKDF-SHA256) known-answer vectors.
// Build/run command at the bottom. Mirrors test_elf_segment.cpp's approach.
#include "dicore/crypto/hkdf.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> v;
    v.reserve(h.size() / 2);
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

bool eq(const uint8_t* a, const std::vector<uint8_t>& b, size_t n) {
    return b.size() == n && std::memcmp(a, b.data(), n) == 0;
}

} // namespace

int main() {
    using namespace dicore::crypto;

    // ---- RFC 4231 HMAC-SHA256 Test Case 1 ------------------------------------
    // Key = 0x0b * 20, Data = "Hi There"
    {
        std::vector<uint8_t> key(20, 0x0b);
        const char* data = "Hi There";
        uint8_t mac[32];
        hmac_sha256(key.data(), key.size(),
                    reinterpret_cast<const uint8_t*>(data), std::strlen(data), mac);
        auto want = unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert(eq(mac, want, 32));
    }

    // ---- RFC 5869 HKDF-SHA256 Test Case 1 (with salt + info) -----------------
    {
        auto ikm  = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");        // 22 x 0x0b
        auto salt = unhex("000102030405060708090a0b0c");                          // 13 bytes
        auto info = unhex("f0f1f2f3f4f5f6f7f8f9");                                // 10 bytes
        uint8_t okm[42];
        assert(hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(),
                           info.data(), info.size(), okm, sizeof(okm)));
        auto want = unhex("3cb25f25faacd57a90434f64d0362f2a"
                          "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                          "34007208d5b887185865");
        assert(eq(okm, want, sizeof(okm)));
    }

    // ---- RFC 5869 HKDF-SHA256 Test Case 3 (empty salt + empty info) ----------
    {
        auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");         // 22 x 0x0b
        uint8_t okm[42];
        assert(hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 0,
                           okm, sizeof(okm)));
        auto want = unhex("8da4e775a563c18f715f802a063c5a31"
                          "b8a11f5c5ee1879ec3454e5f3c738d2d"
                          "9d201395faa4b61a96c8");
        assert(eq(okm, want, sizeof(okm)));
    }

    // ---- Bound check: out_len > 255*32 must be rejected -----------------------
    {
        uint8_t ikm[4] = {1, 2, 3, 4};
        std::vector<uint8_t> big(255 * 32 + 1);
        assert(!hkdf_sha256(ikm, sizeof(ikm), nullptr, 0, nullptr, 0,
                            big.data(), big.size()));
    }

    std::printf("test_hkdf OK\n");
    return 0;
}

/* Build/run (host), with a host shim providing a no-op android/log.h:
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" -I<hostshim> \
         "$CPP/dicore/crypto/test_hkdf.cpp" \
         "$CPP/dicore/crypto/hkdf.cpp" \
         "$CPP/dicore/crypto/sha256.cpp" -o /tmp/test_hkdf && /tmp/test_hkdf */
