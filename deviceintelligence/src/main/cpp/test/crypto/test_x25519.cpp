// Host unit test (KAT) for X25519 — RFC 7748 §5.2 (single scalarmult) and
// §6.1 (Diffie-Hellman). Build/run command at the bottom.
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
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return v;
}
void expect(const uint8_t out[32], const std::string& want_hex) {
    auto want = unhex(want_hex);
    assert(want.size() == 32 && std::memcmp(out, want.data(), 32) == 0);
}
} // namespace

int main() {
    using namespace dicore::crypto;
    uint8_t out[32];

    // RFC 7748 §5.2 vector 1
    {
        auto k = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        auto u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        x25519_scalarmult(out, k.data(), u.data());
        expect(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }
    // RFC 7748 §5.2 vector 2
    {
        auto k = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        auto u = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        x25519_scalarmult(out, k.data(), u.data());
        expect(out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }
    // RFC 7748 §6.1 Diffie-Hellman
    {
        auto a_priv = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        auto b_priv = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        uint8_t a_pub[32], b_pub[32], ka[32], kb[32];
        x25519_base(a_pub, a_priv.data());
        expect(a_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        x25519_base(b_pub, b_priv.data());
        expect(b_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        x25519_scalarmult(ka, a_priv.data(), b_pub);   // Alice * Bob_pub
        x25519_scalarmult(kb, b_priv.data(), a_pub);   // Bob * Alice_pub
        expect(ka, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert(std::memcmp(ka, kb, 32) == 0);          // both sides agree
    }

    std::printf("test_x25519 OK\n");
    return 0;
}

/* Build/run (host), with a host shim providing a no-op android/log.h (not needed
   here — x25519.cpp has no android deps — but kept uniform):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" "$CPP/dicore/crypto/test_x25519.cpp" \
         "$CPP/dicore/crypto/x25519.cpp" -o /tmp/test_x25519 && /tmp/test_x25519 */
