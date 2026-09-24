// Host sanity test for secure_random (not a statistical test — correctness of
// the API contract only). Build/run at the bottom.
#include "dicore/crypto/rand.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

int main() {
    using namespace dicore::crypto;

    uint8_t a[32], b[32];
    std::memset(a, 0, sizeof(a));
    assert(secure_random(a, sizeof(a)));
    assert(secure_random(b, sizeof(b)));

    // Two independent draws must differ, and 32 zero bytes is astronomically
    // unlikely from a working CSPRNG.
    bool all_zero = true;
    for (uint8_t x : a) if (x != 0) { all_zero = false; break; }
    assert(!all_zero);
    assert(std::memcmp(a, b, sizeof(a)) != 0);

    assert(secure_random(nullptr, 0) == true);   // len 0 is a no-op success
    assert(secure_random(nullptr, 4) == false);  // null with len -> false

    std::printf("test_rand OK\n");
    return 0;
}

/* Build/run (host):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" "$CPP/dicore/crypto/test_rand.cpp" \
         "$CPP/dicore/crypto/rand.cpp" -o /tmp/test_rand && /tmp/test_rand */
