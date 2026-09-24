// Host unit tests for the self-owned RFC 1951 inflater (dicore::crypto::inflate).
// Differential: round-trips DEFLATE streams produced by zlib (the reference) across
// stored/fixed/dynamic block types + edge sizes; plus a malformed matrix that must
// fail-closed (nullptr) and never over-read. Build via native-unit-tests.sh.
#include "dicore/crypto/inflate.h"

#include "test_inflate_data.h"      // kInflateVecs / kInflateVecCount

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

int main() {
    using namespace dicore::crypto;

    // ---- differential round-trip vs zlib output ----
    for (int i = 0; i < kInflateVecCount; ++i) {
        const auto& v = kInflateVecs[i];
        size_t produced = 0;
        void* p = inflate_deflate(v.deflated, v.dlen, &produced);
        assert(p != nullptr);                                  // valid stream inflates
        assert(produced == v.olen);                            // exact size match
        if (v.olen) assert(std::memcmp(p, v.orig, v.olen) == 0);
        free(p);
    }

    // Assert the vector set actually spans STORED + FIXED + DYNAMIC blocks
    // (the dynamic path — HLIT/HDIST/HCLEN + repeat codes — is the most complex).
    {
        bool stored=false, fixed=false, dynamic=false;
        for (int i=0;i<kInflateVecCount;++i){ int b=kInflateVecs[i].btype;
            if(b==0)stored=true; else if(b==1)fixed=true; else if(b==2)dynamic=true; }
        assert(stored && fixed && dynamic);   // block-type coverage
    }

    // ---- explicit STORED-block round-trip (LEN=3 "abc", NLEN=~LEN) ----
    {
        uint8_t s[] = {0x01, 0x03,0x00, 0xFC,0xFF, 'a','b','c'};
        size_t n = 0; void* p = inflate_deflate(s, sizeof(s), &n);
        assert(p && n == 3 && std::memcmp(p, "abc", 3) == 0);
        free(p);
    }

    // ---- malformed matrix: every case -> nullptr, no crash ----
    auto rejects = [](const std::vector<uint8_t>& b){
        size_t n = 99; void* p = inflate_deflate(b.data(), b.size(), &n);
        if (p) { free(p); return false; }
        return n == 0;                                         // out_len reset on failure
    };
    assert(inflate_deflate(nullptr, 5, nullptr) == nullptr);   // null input
    assert(rejects({0x06}));                                   // BTYPE=3 (reserved)
    assert(rejects({0x01, 0x05,0x00, 0x00,0x00, 1,2,3,4,5}));  // stored: NLEN != ~LEN
    assert(rejects({0x01, 0x05,0x00, 0xFA,0xFF, 1,2}));        // stored: LEN overruns input
    assert(rejects({}));                                       // empty input (no block header)
    // truncation sweep over a real dynamic stream: every proper prefix fails, no crash.
    {
        const auto& big = kInflateVecs[kInflateVecCount - 1];  // mixed10k / binaryish
        for (size_t k = 0; k < big.dlen; ++k) {
            size_t n = 0; void* p = inflate_deflate(big.deflated, k, &n);
            free(p);                                           // may be null; must not crash
        }
    }

    std::printf("test_inflate OK (%d zlib vectors + malformed matrix)\n", kInflateVecCount);
    return 0;
}
