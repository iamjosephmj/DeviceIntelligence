// Host test for raw_uname. The kernel release is a fingerprint input and a
// spoofer-detection input, so it is read by raw syscall rather than libc: a PLT
// hook on uname() must not be able to forge it.
// Build/run via tools/qa/native-unit-tests.sh.
#include "dicore/platform/syscalls.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/utsname.h>

int main() {
    using namespace dicore::sys;

    struct utsname u {};
    int err = 0;
    assert(raw_uname(&u, &err) == 0);
    assert(err == 0);

    // release must be non-empty and look like a version: leading digit, then a dot.
    assert(u.release[0] != '\0');
    assert(u.release[0] >= '0' && u.release[0] <= '9');
    assert(std::strchr(u.release, '.') != nullptr);

    // sysname on any Linux/Android host is "Linux".
    assert(std::strcmp(u.sysname, "Linux") == 0);

    // Must agree with libc uname() on an unhooked host — this is the parity check
    // that proves the raw syscall path is wired to the right call number.
    struct utsname ref {};
    assert(::uname(&ref) == 0);
    assert(std::strcmp(u.release, ref.release) == 0);

    // A null out pointer must fail cleanly rather than trap.
    int err2 = 0;
    assert(raw_uname(nullptr, &err2) == -1);

    std::printf("test_raw_uname OK (%s)\n", u.release);
    return 0;
}
