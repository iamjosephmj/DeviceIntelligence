#include "dicore/detectors/environment/verdicts/seccomp_verdict.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <vector>

#include "dicore/core/verdict_cores.h"

namespace dicore {

bool kill_probe_indicates_filter(int rc, int err) {
    if (rc == 0) return false;
    return err == EPERM || err == EACCES;
}

// Presence-based, but USER_NOTIF-specific and FP-safe. A SECCOMP_RET_USER_NOTIF
// filter — the /proc-interception primitive used to spoof /proc/self/maps below
// libc — leaves the process HOLDING a listener fd whose readlink resolves to
// "anon_inode:[seccomp notify]". A benign seccomp-bpf policy (the Android app
// filter, RET_ERRNO/TRAP/KILL) leaves NO such fd; a normal app never self-holds a
// seccomp-notify listener. So a self-held notify fd is a high-confidence signal of
// an in-process syscall interceptor — exactly the class the kill(self,0) effect
// probe misses (a filter trapping openat doesn't block kill). Scans /proc/self/fd.
bool seccomp_user_notif_listener_present() {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return false;
    struct dirent* e;
    char link[64], tgt[256];
    bool found = false;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;   // fd entries are numeric
        std::snprintf(link, sizeof(link), "/proc/self/fd/%s", e->d_name);
        ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
        if (n <= 0) continue;
        tgt[n] = '\0';
        if (std::strstr(tgt, "seccomp notify")) { found = true; break; }
    }
    closedir(d);
    return found;
}

// Effect-based, not presence-based. We cannot read an installed seccomp filter's
// contents (BPF programs are write-only; PTRACE_SECCOMP_GET_FILTER needs an
// external tracer, denied on a non-debuggable release process). So rather than
// flag "a filter exists" — which kills legitimate apps that stack their own
// benign filter and protects nothing (the removed enforcement kill's wild-write detonate is
// unfilterable) — we probe the EFFECT on the one syscall our defense cares about:
// kill. Baseline Android app policy permits kill(self,0), so EPERM/EACCES means a
// filter is actively blocking kill — a hostile, high-confidence tamper signal. A
// benign allow-all filter passes the probe and is correctly ignored.
std::vector<std::string> seccomp_verdict_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    int rc = kill(getpid(), 0);
    int saved_errno = errno;
    if (kill_probe_indicates_filter(rc, saved_errno)) {
        out.push_back(std::string("seccomp_kill_filtered") + kFS + "CRITICAL" + kFS +
                      "errno=" + std::to_string(saved_errno));
    }

    // USER_NOTIF interceptor: a self-held seccomp-notify listener fd (the /proc-spoof
    // primitive the kill probe above cannot see).
    if (seccomp_user_notif_listener_present()) {
        out.push_back(std::string("seccomp_user_notif_listener") + kFS + "CRITICAL" + kFS +
                      "self-held SECCOMP_RET_USER_NOTIF listener fd (syscall interception)");
    }
    return out;
}

}  // namespace dicore
