// Host unit test for the crash-safe code-memory reader.
//
// WHY: on Android 10 arm64 the platform maps libart's .text EXECUTE-ONLY (no
// PROT_READ). A plain memcpy of a function prologue then dies with
// SIGSEGV/SEGV_ACCERR — which is exactly how the app crashed at JNI_OnLoad on a
// Samsung Tab S5e (gts4lvwifi:10). Every read of foreign code must therefore go
// through a path that RETURNS AN ERROR instead of faulting the process.
//
// The host cannot reproduce execute-only mappings portably, so what is asserted
// here is the contract that matters and is testable everywhere: readable memory
// round-trips exactly, and an unreadable address FAILS rather than crashing.
//
// Build/run at the bottom.
#include "dicore/platform/safe_text_read.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

using namespace dicore::platform;

int main() {
    // 1. Ordinary readable memory round-trips byte for byte.
    const uint8_t src[16] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
                             5, 6, 7, 8, 0xca, 0xfe, 0xba, 0xbe};
    uint8_t dst[16] = {};
    assert(safe_read_code(src, dst, sizeof(dst)));
    assert(std::memcmp(src, dst, sizeof(dst)) == 0);

    // 2. A PROT_NONE page is READ SUCCESSFULLY, and that is the point rather than a
    //    bug: /proc/self/mem is serviced with FOLL_FORCE, so it reads through page
    //    protections. This is the property that lets us read execute-only .text on
    //    Android 10+ instead of merely failing gracefully. A plain memcpy here would
    //    have taken SIGSEGV and killed the process.
    void* p = mmap(nullptr, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    uint8_t out[16] = {0xff};
    assert(safe_read_code(p, out, sizeof(out)));
    munmap(p, 4096);

    // 2b. An UNMAPPED address must fail — cleanly, by return value, never a signal.
    //     (Mapped then unmapped, so the address is known not to be backed.)
    void* gone = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(gone != MAP_FAILED);
    munmap(gone, 4096);
    assert(!safe_read_code(gone, out, sizeof(out)));

    // 3. A null / zero-length request is rejected rather than UB.
    assert(!safe_read_code(nullptr, dst, sizeof(dst)));
    assert(!safe_read_code(src, dst, 0));

    // 4. Reads spanning a page boundary work (prologues can straddle pages).
    uint8_t* two = static_cast<uint8_t*>(
        mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    assert(two != MAP_FAILED);
    for (int i = 0; i < 8192; ++i) two[i] = static_cast<uint8_t>(i);
    uint8_t span[16] = {};
    assert(safe_read_code(two + 4096 - 8, span, sizeof(span)));
    for (int i = 0; i < 16; ++i) assert(span[i] == static_cast<uint8_t>(4096 - 8 + i));
    munmap(two, 8192);

    std::printf("test_safe_text_read OK\n");
    return 0;
}

/* Build/run:
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" "$CPP/test/platform/test_safe_text_read.cpp" \
       "$CPP/dicore/platform/safe_text_read.cpp" \
       -o /tmp/test_safe_text_read && /tmp/test_safe_text_read */
