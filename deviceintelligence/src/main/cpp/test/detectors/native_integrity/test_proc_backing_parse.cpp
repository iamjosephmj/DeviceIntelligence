// Host unit test for the pure /proc parsers (no JNI/syscalls).
// Build/run command at the bottom (NDK clang static — host clang++ not installed).
#include "dicore/detectors/native_integrity/system_libs/proc_backing_parse.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace dicore::native_integrity;

static bool maps(const char* s, uint32_t* mj, uint32_t* mn) {
    return parse_maps_libc_dev(s, std::strlen(s), mj, mn);
}
static bool apex(const char* s, ApexMount* o) {
    return parse_mountinfo_apex(s, std::strlen(s), o);
}

int main() {
    uint32_t mj = 0, mn = 0;

    // libc maps line: dev field "07:c0" is HEX -> 7 / 192.
    assert(maps("7d3f8b7000-7d3f953000 r-xp 00056000 07:c0 41 "
                "/apex/com.android.runtime/lib64/bionic/libc.so", &mj, &mn));
    assert(mj == 7 && mn == 192);

    // non-libc mapping -> false.
    assert(!maps("7d00-7d01 r-xp 0 07:c0 9 /apex/com.android.runtime/lib64/libart.so", &mj, &mn));
    // libc++ must NOT match "/libc.so".
    assert(!maps("7d00-7d01 r-xp 0 07:c0 9 /system/lib64/libc++.so", &mj, &mn));
    // libcutils.so must NOT match "/libc.so".
    assert(!maps("7d00-7d01 r-xp 0 07:c0 9 /system/lib64/libcutils.so", &mj, &mn));
    // Malformed dev tokens -> parse fails (false).
    assert(!maps("7d00-7d01 r-xp 0 :192 9 /apex/com.android.runtime/lib64/bionic/libc.so", &mj, &mn));
    assert(!maps("7d00-7d01 r-xp 0 07: 9 /apex/com.android.runtime/lib64/bionic/libc.so", &mj, &mn));
    // Overflow-long device field -> parse fails (false).
    assert(!maps("7d00-7d01 r-xp 0 100000000:0 9 /apex/com.android.runtime/lib64/bionic/libc.so", &mj, &mn));

    ApexMount m{};
    // genuine apex mount: decimal "7:192", ro, ext4, /dev/block source.
    assert(apex("175 51 7:192 / /apex/com.android.runtime ro,nodev,noatime - "
                "ext4 /dev/block/loop24 ro,seclabel", &m));
    assert(m.major == 7 && m.minor == 192 && m.ro && m.fstype_ok && m.source_devblock);

    // versioned/other mountpoint -> not the container, false.
    assert(!apex("172 51 7:192 / /apex/com.android.runtime@1 ro,nodev - ext4 /dev/block/loop24 ro", &m));
    assert(!apex("30 1 0:23 / /data rw,nosuid - f2fs /dev/block/dm-5 rw", &m));

    // tampered apex mounts -> matched but flagged.
    ApexMount t{};
    assert(apex("99 51 0:44 / /apex/com.android.runtime rw,nosuid - overlay overlay rw", &t));
    assert(!t.fstype_ok && !t.source_devblock && !t.ro);  // overlay + rw + non-/dev/block

    ApexMount t2{};
    assert(apex("98 51 0:9 / /apex/com.android.runtime ro,nodev - tmpfs tmpfs ro", &t2));
    assert(t2.ro && !t2.fstype_ok && !t2.source_devblock);  // tmpfs fstype + tmpfs source

    printf("all proc_backing_parse tests passed\n");
    return 0;
}
// Build & run (host, via NDK clang static):
//   NDKCXX="$HOME/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang++"
//   "$NDKCXX" -std=c++17 -static -static-libstdc++ -Wall -Wextra -Werror -Wno-unused-parameter -fno-rtti -fno-exceptions \
//     -I deviceintelligence/src/main/cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/native_integrity/test_proc_backing_parse.cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/native_integrity/system_libs/proc_backing_parse.cpp \
//     -o /tmp/test_pbp && /tmp/test_pbp
