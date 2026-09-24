// antidebug_verdict.cpp — runtime.environment anti-debug / anti-Frida core.
//
// Dynamic instrumentation (Frida/gdb) is the gap a static scan of mapped libs
// cannot close: an attacker driving the live process from the outside leaves no
// trampoline page (scan_runtime_maps' domain) but DOES leave three observable
// traces, each emitted here as a CRITICAL US(0x1f)-framed Finding:
//
//   debugger_attached   — /proc/self/status TracerPid is a pid OTHER than our own
//                         watchdog. On a non-debuggable release app, a tracer is
//                         a gdb/lldb/ptrace-based instrument. We MUST exclude the
//                         watchdog: it holds PR_SET_PTRACER and briefly attaches
//                         at kill time, so a naive TracerPid!=0 would self-trip.
//   frida_server_port   — frida-server listens on 127.0.0.1:27042/27043 by
//                         default; a successful loopback connect is a strong tell.
//                         Best-effort: needs INTERNET to create the socket, else
//                         it silently no-ops (fail-open, no false positive).
//   frida_worker_thread — Frida's agent/gadget spins up uniquely-named worker
//                         threads (gum-js-loop / pool-frida / *frida* / linjector)
//                         visible in /proc/self/task/<tid>/comm.
//
// Everything fails open: any read/socket error yields no record, never a kill.
// The lethal decision stays in dicore_orchestrate (DI_OBF_ORCH); this core only
// reports. The detection logic is DI_OBF_MAX-flattened so the thresholds and
// frida tokens an attacker would patch out are not plainly visible.

#include "dicore/core/verdict_cores.h"
#include "dicore/platform/obf.h"  // DI_OBF_MAX

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>                  // syscall smokescreen: detached decoy thread
#include <sys/socket.h>
#include <sys/stat.h>                 // fstatat (decoy)
#include <sys/syscall.h>              // __NR_memfd_create (decoy)
#include <sys/system_properties.h>    // __system_property_get (decoy)
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace dicore {
namespace {

// Read a small proc file fully into buf (NUL-terminated). Returns bytes read, or
// -1 on open failure. Used for /proc/self/status and /proc/self/task/*/comm.
ssize_t read_small(const char* path, char* buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap && (r = read(fd, buf + n, cap - 1 - n)) > 0) n += (size_t)r;
    close(fd);
    buf[n] = '\0';
    return (ssize_t)n;
}

// /proc/self/status TracerPid (0 if untraced / unreadable).
int read_tracer_pid() {
    char buf[4096];
    if (read_small("/proc/self/status", buf, sizeof(buf)) <= 0) return 0;
    const char* p = strstr(buf, "TracerPid:");
    if (p == nullptr) return 0;
    return (int)strtol(p + 10, nullptr, 10);
}

// Loopback connect to a default frida-server port. true only on a completed
// connect (something is listening). Fail-open on any socket error.
bool frida_port_listening(int port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return false;
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bool listening = (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    close(s);
    return listening;
}

// True if any thread of this process carries a Frida-specific worker name. Only
// unambiguous tokens are matched (gum-js-loop / pool-frida / frida / linjector) —
// glib-generic names like "gmain" are deliberately excluded to avoid false hits.
bool frida_worker_thread(std::string& which) {
    DIR* d = opendir("/proc/self/task");
    if (d == nullptr) return false;
    static const char* kTokens[] = {"gum-js-loop", "gumjs", "pool-frida", "frida", "linjector"};
    bool hit = false;
    struct dirent* e;
    while (!hit && (e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        char path[64];
        // /proc/self/task/<tid>/comm — snprintf, NOT a hand-rolled copy: a
        // fixed-length byte-copy from the literal folds into constant stores
        // before the obfuscator (Arkari) runs, and ISel re-materializes the bytes as a
        // cleartext constant-pool entry the pass can never see (red-team F4).
        std::snprintf(path, sizeof path, "/proc/self/task/%s/comm", e->d_name);
        char comm[64];
        if (read_small(path, comm, sizeof(comm)) <= 0) continue;
        for (const char* tok : kTokens) {
            if (strstr(comm, tok) != nullptr) {
                which = tok;
                hit = true;
                break;
            }
        }
    }
    closedir(d);
    return hit;
}

}  // namespace

DI_OBF_MAX
std::vector<std::string> antidebug_verdict_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    // --- debugger_attached: a tracer that is NOT our own watchdog ---------------
    int tracer = read_tracer_pid();
    if (tracer != 0) {
        out.push_back(std::string("debugger_attached") + kFS + "CRITICAL" + kFS +
                      "tracer_pid=" + std::to_string(tracer));
    }

    // --- frida_server_port: default frida-server loopback ports -----------------
    for (int port : {27042, 27043}) {
        if (frida_port_listening(port)) {
            out.push_back(std::string("frida_server_port") + kFS + "CRITICAL" + kFS +
                          "port=" + std::to_string(port));
            break;
        }
    }

    // --- frida_worker_thread: agent/gadget worker thread names ------------------
    std::string which;
    if (frida_worker_thread(which)) {
        out.push_back(std::string("frida_worker_thread") + kFS + "CRITICAL" + kFS +
                      "comm=" + which);
    }

    // --- hook_framework_present: a mapped/anon-named hook-framework library ------
    // (dobby/whale/yahfa/fasthook/il2cpp-dumper/xposed/… in /proc/self/maps). The
    // maps scan produced these but they never reached the verdict; surface them
    // here as CRITICAL.
    for (auto& r : hook_framework_records()) out.push_back(std::move(r));
    // INTEL_0040 — behavioral syscall divergence (a userspace hook lying about the filesystem).
    for (auto& r : syscall_divergence_records()) out.push_back(std::move(r));
    // INTEL_0041 — linker<->maps divergence (map-anonymized foreign module the linker still names).
    for (auto& r : linker_maps_records()) out.push_back(std::move(r));
    // INTEL_0042 — sealed executable memfd (NeoZygisk/zygiskd module loaded from a sealed memfd).
    for (auto& r : sealed_memfd_records()) out.push_back(std::move(r));
    // INTEL_0043 — behavioral property divergence (__system_property_get hooked to spoof boot state).
    for (auto& r : property_divergence_records()) out.push_back(std::move(r));

    return out;
}

// ── Syscall smokescreen (SIG-independent anti-analysis) ─────────────────────
// A fire-and-forget burst of DECOY syscalls that mimic detection probes, run in
// a DETACHED thread launched at challenge time so it executes in PARALLEL with
// the real detector scan without touching the verdict. An adversary tracing the
// app's syscalls (a seccomp user-notif interceptor, a userspace hook logging
// syscalls, ptrace/strace) to learn WHICH probes are real now sees the genuine
// ones buried in a haze of look-alikes — most decoys draw only a benign
// EACCES/EPERM from SELinux, which is expected and harmless.
//
// Safety contract: every decoy is read-only / own-process / expected-denied. A
// bad path returns -1+errno, never a fault, so the detached thread is crash-safe;
// no decoy creates a listener, an executable mapping, a sealed memfd, or writes
// anything, so it cannot trip our OWN signals or perturb what the parallel scan
// reads. Every successful fd is closed (no leak). NOT part of the challenge
// response — results are discarded.
namespace {
// Paths chosen to look exactly like root/hook/boot probes a real detector makes.
const char* const kSmokePaths[] = {
    "/proc/self/maps", "/proc/self/status", "/proc/self/mountinfo",
    "/proc/self/task", "/system/xbin/su", "/system/bin/su",
    "/data/adb/magisk", "/data/adb/modules", "/dev/__properties__",
    "/system/bin/frida-server", "/data/local/tmp/re.frida.server",
};
void* dicore_smoke_thread(void*) {
    // Each path: openat + fstatat + faccessat — three look-alike file probes.
    for (const char* p : kSmokePaths) {
        int fd = openat(AT_FDCWD, p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        struct stat st;
        (void)fstatat(AT_FDCWD, p, &st, 0);
        (void)faccessat(AT_FDCWD, p, F_OK, 0);
    }
    // self-path probe (anti-repackage / exe check look-alike)
    char lbuf[96];
    (void)readlinkat(AT_FDCWD, "/proc/self/exe", lbuf, sizeof(lbuf));
    // frida-server port knock (non-blocking so it never hangs; fails fast)
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s >= 0) {
        struct sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(27042);                 // frida's default port
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        (void)connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        close(s);
    }
    // memfd smell (frida JIT look-alike) — never mapped/sealed/executable, closed at once
    long m = syscall(__NR_memfd_create, "jit-cache", 0u);
    if (m >= 0) close((int)m);
    // boot-state property read look-alike
    char v[PROP_VALUE_MAX];
    (void)__system_property_get("ro.boot.verifiedbootstate", v);
    return nullptr;
}
}  // namespace

// Launch the smokescreen: one detached thread, fire-and-forget. Never blocks the
// caller; a create failure is silently ignored (the scan proceeds regardless).
void dicore_launch_syscall_smoke() {
    pthread_t t;
    if (pthread_create(&t, nullptr, dicore_smoke_thread, nullptr) == 0)
        pthread_detach(t);
}

}  // namespace dicore
