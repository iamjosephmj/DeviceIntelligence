// deviceintelligence/src/main/cpp/test/detectors/environment/test_anon_exec.cpp
#include <cstdio>
#include <cstring>
#include "dicore/detectors/environment/maps/anon_exec.hpp"

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main() {
    using namespace dicore::anon_exec;
    // Legit file-backed exec: not a finding
    const char* m1 =
        "7a10000000-7a10002000 r-xp 00000000 fe:36 1234  /data/app/lib/arm64-v8a/libdicore.so\n";
    Finding f[8];
    CHECK(classify(m1, f, 8) == 0);
    // Anon RWX (the curried-stub pattern): finding
    const char* m2 =
        "7a10000000-7a10002000 r--p 00000000 00:00 0  \n"
        "7a20000000-7a20001000 rwxp 00000000 00:00 0  \n";
    CHECK(classify(m2, f, 8) == 1);
    CHECK(f[0].start == 0x7a20000000ULL && f[0].end == 0x7a20001000ULL);
    CHECK(f[0].perms[1] == 'w' && f[0].perms[2] == 'x');
    CHECK(!f[0].memfd);
    // memfd-backed exec (frida gadget): finding, memfd=true
    const char* m3 =
        "7a30000000-7a30005000 r-xp 00000000 00:0e 99  /memfd:gadget (deleted)\n";
    CHECK(classify(m3, f, 8) == 1);
    CHECK(f[0].memfd);
    CHECK(std::strstr(f[0].path, "memfd") != nullptr);
    // vdso/vvar/vectors excluded
    const char* m4 =
        "7a40000000-7a40001000 r-xp 00000000 00:00 0  [vdso]\n"
        "7a41000000-7a41001000 r-xp 00000000 00:00 0  [vvar]\n"
        "7a42000000-7a42001000 r-xp 00000000 00:00 0  [vectors]\n";
    CHECK(classify(m4, f, 8) == 0);
    // anon exec read-only (JIT art uses named mappings) — anon+r-x with no name IS a finding
    const char* m5 =
        "7a50000000-7a50001000 r-xp 00000000 00:00 0  \n";
    CHECK(classify(m5, f, 8) == 1);
    // capacity respected
    const char* m6 =
        "7a60000000-7a60001000 rwxp 00000000 00:00 0  \n"
        "7a61000000-7a61001000 rwxp 00000000 00:00 0  \n";
    CHECK(classify(m6, f, 1) == 1);
    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
