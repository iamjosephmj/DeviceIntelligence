// Host unit test for the pure seccomp_verdict helper. Not built by gradle;
// compiled directly with host clang++ (see run command below). The pure
// function uses only <cerrno>, so it builds & runs on host.
#include "dicore/detectors/environment/verdicts/seccomp_verdict.h"

#include <cassert>
#include <cerrno>
#include <cstdio>

int main() {
    using namespace dicore;

    // kill_probe_indicates_filter: only an EPERM/EACCES on an otherwise-permitted
    // kill(self,0) indicates a hostile filter; success or any other errno does not.
    assert(kill_probe_indicates_filter(0, 0) == false);       // success
    assert(kill_probe_indicates_filter(-1, EPERM) == true);   // filtered
    assert(kill_probe_indicates_filter(-1, EACCES) == true);  // filtered
    assert(kill_probe_indicates_filter(-1, ESRCH) == false);  // other errno -> fail-open

    printf("all seccomp_verdict pure-helper tests passed\n");
    return 0;
}
