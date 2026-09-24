// Host unit test for the anonymous-executable maps-line parser (no JNI/syscalls).
//
// WHY this exists: on kernels without PR_SET_VMA_ANON_NAME the ART JIT code cache
// appears in /proc/self/maps as an UNNAMED executable mapping, e.g.
//   9ac8d000-9cc8d000 r-xp 00000000 00:00 0
// The old parser dropped every unnamed line, so the JIT cache was never collected
// (jit=0) and every JIT-compiled entry point classified UNKNOWN — firing vector A
// on a clean device. These lines must now be recognised so they can be baselined.
//
// Build/run at the bottom.
#include "dicore/detectors/art_integrity/runtime/ranges.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace dicore::art_integrity;

static bool anon(const char* s, uintptr_t* a, uintptr_t* b) {
    return maps_line_is_anon_exec(s, a, b);
}

int main() {
    uintptr_t start = 0, end = 0;

    // The real line from the Lenovo Android 9 tablet: unnamed, executable, 32 MiB.
    assert(anon("9ac8d000-9cc8d000 r-xp 00000000 00:00 0", &start, &end));
    assert(start == 0x9ac8d000UL && end == 0x9cc8d000UL);

    // Trailing whitespace after the inode is still an anonymous mapping.
    assert(anon("9ac8d000-9cc8d000 r-xp 00000000 00:00 0    ", &start, &end));
    assert(start == 0x9ac8d000UL);

    // 64-bit addresses parse.
    assert(anon("7d1f0b4000-7d1f0b5000 r-xp 00000000 00:00 0", &start, &end));
    assert(start == 0x7d1f0b4000UL && end == 0x7d1f0b5000UL);

    // NOT anonymous: a named mapping, even though it is executable. Those are
    // classified by path elsewhere and must not land in the anon bucket.
    assert(!anon("7113f000-71140000 r-xp 00000000 fd:00 123 "
                 "/system/framework/arm64/boot.oat", &start, &end));
    assert(!anon("9ac8d000-9cc8d000 r-xp 00000000 00:00 0 [anon:jit-code-cache]",
                 &start, &end));

    // NOT executable -> not our bucket (heap, stacks, data).
    assert(!anon("9ac8d000-9cc8d000 rw-p 00000000 00:00 0", &start, &end));
    assert(!anon("9ac8d000-9cc8d000 r--p 00000000 00:00 0", &start, &end));

    // Malformed lines must fail rather than yield garbage ranges.
    assert(!anon("", &start, &end));
    assert(!anon("not-a-maps-line", &start, &end));
    assert(!anon("9ac8d000 r-xp 00000000 00:00 0", &start, &end));

    // Zero-length range is not a usable range.
    assert(!anon("9ac8d000-9ac8d000 r-xp 00000000 00:00 0", &start, &end));

    std::printf("test_anon_exec_maps OK\n");
    return 0;
}

/* Build/run (NDK clang static, matching test/detectors/native_integrity):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" \
       "$CPP/test/detectors/art_integrity/test_anon_exec_maps.cpp" \
       "$CPP/dicore/detectors/art_integrity/runtime/ranges.cpp" \
       -o /tmp/test_anon_exec_maps && /tmp/test_anon_exec_maps */
