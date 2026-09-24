#pragma once

namespace dicore {

// Decide whether the kill(getpid(), 0) result indicates a filter blocking an
// otherwise-permitted syscall. Baseline Android app policy permits kill(self,0),
// so EPERM/EACCES means kill is being filtered. rc==0 => not filtered.
// Pure / syscall-free — unit-tested on host.
bool kill_probe_indicates_filter(int rc, int err);

}  // namespace dicore
