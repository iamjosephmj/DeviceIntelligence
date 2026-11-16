// Host test for the fingerprint pepper + hash. Build/run via
// tools/qa/native-unit-tests.sh.
#include "dicore/crypto/fp_pepper.h"
#include "dicore/crypto/licence_blob.h"
#include "dicore/crypto/sha256.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

int main() {
    using namespace dicore::crypto;

    LicenceKey k{};
    for (int i = 0; i < 32; ++i) k.pubkey[i] = static_cast<uint8_t>(i);

    uint8_t p1[32], p2[32];
    fp_pepper(k, p1);
    fp_pepper(k, p2);
    assert(std::memcmp(p1, p2, 32) == 0);           // deterministic

    // Must equal SHA-256("intel-fp-pepper-v1" || pubkey) exactly.
    const char kInfo[] = "intel-fp-pepper-v1";
    const size_t kInfoLen = std::strlen(kInfo);   // must match fp_pepper.cpp's sizeof-1 use
    uint8_t buf[18 + 32], want[32];
    static_assert(sizeof(kInfo) - 1 == 18, "info phrase length drifted");
    std::memcpy(buf, kInfo, kInfoLen);
    std::memcpy(buf + kInfoLen, k.pubkey, 32);
    assert(dicore::sha::sha256(buf, sizeof(buf), want));
    assert(std::memcmp(p1, want, 32) == 0);

    // A different key gives a different pepper — this is what scopes the id.
    LicenceKey k2 = k; k2.pubkey[0] ^= 0xff;
    uint8_t p3[32]; fp_pepper(k2, p3);
    assert(std::memcmp(p1, p3, 32) != 0);

    // fp_hash: stable, 64 lowercase hex chars, differs per input.
    std::string a, b, c;
    assert(fp_hash(p1, "abc", &a));
    assert(fp_hash(p1, "abc", &b));
    assert(a == b && a.size() == 64);
    for (char ch : a) assert((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'));
    assert(fp_hash(p1, "abd", &c) && c != a);

    // A different pepper gives a different hash for the same value.
    std::string d; assert(fp_hash(p3, "abc", &d)); assert(d != a);

    // Empty input must FAIL, not hash "" — an unreadable identifier is absent,
    // not a value every such device would share.
    std::string e = "untouched";
    assert(!fp_hash(p1, "", &e));
    assert(e == "untouched");

    std::printf("test_fp_pepper OK\n");
    return 0;
}
