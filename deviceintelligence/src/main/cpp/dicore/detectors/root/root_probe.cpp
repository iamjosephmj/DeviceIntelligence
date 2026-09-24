// root_probe.cpp — native runtime.root channels (spec 03 S2b port).
//
// The root-detection DECISION (which paths/mounts/sockets/props indicate root,
// and at what severity) moves out of Kotlin (RootIndicatorsDetector) into C++.
// Native walks the filesystem + /proc, classifies, assigns severity, and returns
// ready-to-marshal Finding records; Kotlin only wraps them. Channels ported:
//   su_binary_present (HIGH), magisk_artifact_present (HIGH),
//   magisk_in_init_mountinfo (HIGH), magisk_daemon_socket_present (HIGH),
//   tls_trust_store_tampered (CRITICAL), test_keys_build (MEDIUM).
// NOT here: the root-manager-app check stays in Kotlin (PackageManager is
// framework-only → S3); the `which su` Runtime.exec channel is DROPPED
// (spec §8 — SELinux/noexec fragile, the path+$PATH walk covers the same ground).
//
// Read/stat failures degrade to "no signal" — never escalated into a finding.

#include <jni.h>
#include <sys/prctl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "dicore/platform/svc_io.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace dicore {
namespace {

constexpr char kFS = '\x1f';  // US record separator (matches the other ports)

const char* const kHardcodedSuPaths[] = {
    "/sbin/su", "/system/bin/su", "/system/xbin/su", "/system/sbin/su",
    "/vendor/bin/su", "/data/local/tmp/su", "/data/local/bin/su",
    "/data/local/su", "/su/bin/su", "/cache/su",
};

const char* const kMagiskPaths[] = {
    "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
    "/data/adb/magisk.db", "/data/data/com.topjohnwu.magisk",
};

// Existence probe via the raw-svc layer (B3): libc access() is a PLT symbol,
// so an in-process hook could blind exactly this channel (hide the su binary
// / magisk artifacts by faking ENOENT). The raw openat probe has no libc
// symbol to interpose. No call site distinguishes EACCES from ENOENT — both
// are plain "absent" — so the fd>=0 existence contract preserves every
// branch.
bool file_exists(const char* path) { return svc::exists(path); }

// Read a (small) proc/text file in full; "" on failure. Cap to avoid a runaway
// read on a pathological /proc file.
//
// B3: raw-syscall read — every /proc channel below (mounts, mountinfo,
// net/unix) is a root-hiding target, and a libc fopen/fread hook is exactly
// how Shamiko-class hiders would sanitize them. Cap breach now fails (""), it
// no longer returns a truncated prefix — every file read here is far under
// the cap, and a truncated mount table would under-report, never over-report.
std::string read_text(const char* path, size_t cap = 1u << 20) {
    std::string out;
    svc::read_file(path, &out, cap);
    return out;
}

bool contains_ci(const std::string& hay, const char* needle) {
    std::string h = hay, n = needle;
    for (auto& c : h) c = (char)std::tolower((unsigned char)c);
    for (auto& c : n) c = (char)std::tolower((unsigned char)c);
    return h.find(n) != std::string::npos;
}

std::string nth_field(const std::string& line, int idx) {  // space-delimited, 0-based
    size_t pos = 0;
    for (int i = 0; ; ++i) {
        size_t sp = line.find(' ', pos);
        if (i == idx) return line.substr(pos, (sp == std::string::npos ? line.size() : sp) - pos);
        if (sp == std::string::npos) return "";
        pos = sp + 1;
    }
}

void for_each_line(const std::string& content, const std::function<void(const std::string&)>& fn) {
    size_t pos = 0;
    while (pos < content.size()) {
        size_t eol = content.find('\n', pos);
        size_t end = (eol == std::string::npos) ? content.size() : eol;
        if (end > pos) fn(content.substr(pos, end - pos));
        pos = (eol == std::string::npos) ? content.size() : eol + 1;
    }
}

std::string record(const char* kind, const char* sev, const char* msg,
                   const std::string& detail) {
    std::string r = kind;
    r += kFS; r += sev;
    r += kFS; r += msg;
    r += kFS; r += detail;
    return r;
}

}  // namespace

// Native runtime.root verdict core (shared by the Kotlin-driven JNI and the
// native orchestrator): walk the filesystem + /proc channels, classify, and
// return the Finding records. The only CRITICAL channel is
// tls_trust_store_tampered. The root-manager-app channel (MEDIUM, needs a
// PackageManager query) stays JNI-only.
std::vector<std::string> root_verdict_records() {
    std::vector<std::string> recs;

    // ---- Channel 1: su binary (hardcoded paths + $PATH walk) ----------------
    std::vector<std::string> su_seen;
    auto add_su = [&](const std::string& p) {
        for (const auto& s : su_seen) if (s == p) return;
        su_seen.push_back(p);
        recs.push_back(record("su_binary_present", "HIGH",
                              "An `su` binary was found at a known root-tool path", "path=" + p));
    };
    for (const char* p : kHardcodedSuPaths) if (file_exists(p)) add_su(p);
    if (const char* path_env = getenv("PATH")) {
        std::string pe(path_env), dir;
        size_t pos = 0;
        while (pos <= pe.size()) {
            size_t col = pe.find(':', pos);
            size_t end = (col == std::string::npos) ? pe.size() : col;
            dir = pe.substr(pos, end - pos);
            if (!dir.empty()) {
                std::string cand = (dir.back() == '/') ? (dir + "su") : (dir + "/su");
                if (file_exists(cand.c_str())) add_su(cand);
            }
            if (col == std::string::npos) break;
            pos = col + 1;
        }
    }

    // ---- Channel 2: Magisk artifacts (files + /proc/mounts) ------------------
    for (const char* p : kMagiskPaths) {
        if (file_exists(p))
            recs.push_back(record("magisk_artifact_present", "HIGH",
                                  "Magisk-related artifact present on device",
                                  std::string("artifact=path=") + p));
    }
    for_each_line(read_text("/proc/mounts"), [&](const std::string& line) {
        if (!contains_ci(line, "magisk")) return;
        std::string target = nth_field(line, 1);
        if (!target.empty())
            recs.push_back(record("magisk_artifact_present", "HIGH",
                                  "Magisk-related artifact present on device",
                                  "artifact=mount=" + target));
    });

    // ---- Channel 3: Magisk in init (PID 1) mount namespace ------------------
    for_each_line(read_text("/proc/1/mountinfo"), [&](const std::string& line) {
        if (!contains_ci(line, "magisk")) return;
        std::string mp = nth_field(line, 4);
        if (!mp.empty())
            recs.push_back(record("magisk_in_init_mountinfo", "HIGH",
                                  "Magisk artefact present in /proc/1/mountinfo "
                                  "(Shamiko cannot hide init's mount namespace)",
                                  "artifact=mountpoint=" + mp));
    });

    // ---- Channel 4: Magisk daemon abstract socket ---------------------------
    {
        std::string unix_tbl = read_text("/proc/self/net/unix");
        if (unix_tbl.find("@magisk_daemon") != std::string::npos)
            recs.push_back(record("magisk_daemon_socket_present", "HIGH",
                                  "Magisk daemon abstract Unix socket @magisk_daemon is bound "
                                  "(visible even when filesystem artefacts are hidden)",
                                  "socket_name=@magisk_daemon"));
    }

    // ---- Channel 5: TLS trust-store tamper (conscrypt tmpfs) — CRITICAL ------
    for_each_line(read_text("/proc/self/mountinfo"), [&](const std::string& line) {
        if (line.find("/apex/com.android.conscrypt") == std::string::npos) return;
        size_t dash = line.find(" - ");
        if (dash == std::string::npos) return;
        std::string fstype = nth_field(line.substr(dash + 3), 0);
        if (fstype != "tmpfs") return;
        std::string mp = nth_field(line.substr(0, dash), 4);
        if (!mp.empty())
            recs.push_back(record("tls_trust_store_tampered", "CRITICAL",
                                  "tmpfs bind-mount over /apex/com.android.conscrypt — system TLS "
                                  "trust store has been swapped, MITM-enabling",
                                  "artifact=mountpoint=" + mp));
    });

    // ---- Channel 6: ro.build.tags == test-keys (MEDIUM) ---------------------
    {
        char tags[PROP_VALUE_MAX] = {0};
        int n = __system_property_get("ro.build.tags", tags);
        if (n > 0 && std::strstr(tags, "test-keys"))
            recs.push_back(record("test_keys_build", "MEDIUM",
                                  "ro.build.tags reports a test-keys signed build "
                                  "(custom ROM or eng build)",
                                  std::string("ro_build_tags=") + tags));
    }

    // ---- Channel 6b: SELinux in permissive mode — CRITICAL ------------------
    // A genuine consumer device runs SELinux Enforcing; permissive (enforce=0)
    // means a modified kernel / userdebug-eng build or a live `setenforce 0` —
    // all root/tamper enablers. Proof-positive: no production device is
    // permissive. Fail-open by construction: in Enforcing mode an app is usually
    // DENIED reading this node (-> "" -> no finding), whereas permissive lets the
    // read through, so the "0" is visible exactly when it matters. `re` on read
    // failure yields "".
    {
        std::string enforce = read_text("/sys/fs/selinux/enforce", 8);
        if (!enforce.empty() && enforce[0] == '0')
            recs.push_back(record("selinux_permissive", "CRITICAL",
                                  "SELinux is in permissive mode (enforce=0) — genuine "
                                  "consumer devices are always Enforcing",
                                  "enforce=0"));
    }

    // ---- Channel 7: su on a read-only system partition — CRITICAL -----------
    // A su binary baked into /system, /sbin, /vendor or /su is unambiguous root:
    // production builds never ship one, and those partitions are not writable
    // without root — so unlike a /data/local/tmp/su (which non-root malware could
    // plant, hence HIGH in Channel 1) this is a definitive compromise. Catches
    // kernel-root setups (KernelSU / Magisk) that mount su there even when the
    // kernel hides its other traces — including hardened KernelSU that evades the
    // magic-prctl probe below.
    {
        const char* const kSystemSuPaths[] = {
            "/system/bin/su", "/system/xbin/su", "/system/sbin/su",
            "/sbin/su", "/vendor/bin/su", "/su/bin/su",
        };
        for (const char* p : kSystemSuPaths) {
            if (file_exists(p))
                recs.push_back(record("su_binary_system_path", "CRITICAL",
                                      "An su binary is present on a read-only system partition",
                                      std::string("path=") + p));
        }
    }

    // ---- Channel 8: KernelSU — kernel-level root — CRITICAL ------------------
    // KernelSU leaves NO su binary and NO Magisk filesystem artefact (Channels
    // 1-4 miss it); the root lives in the kernel. It intercepts prctl() on its
    // magic option (0xDEADBEEF) and, for CMD_GET_VERSION (2), writes its version
    // back through the arg3 user pointer. A stock kernel returns EINVAL and never
    // touches the buffer, so a non-zero version is an unambiguous KernelSU signal
    // (near-zero false-positive — nothing else handles that option). Best-effort:
    // the very latest KernelSU adds manager-only gating that can suppress this, so
    // absence is not proof of cleanliness — but a hit is decisive. CRITICAL,
    // matching the kernel-level severity (parity with tls_trust_store_tampered).
    // EMPIRICALLY (2026-08, KernelSU-Next + Integrity-Box on a Pixel 6 Pro): the
    // magic prctl is FULLY gated for unprivileged callers — every cmd returns -1/EINVAL,
    // byte-identical to a stock kernel (no version, no reply, no errno differential). So
    // KSU-Next is invisible to any userspace syscall probe here; such a device is caught
    // instead by the BACKEND attestation gates (a TrickyStore keybox fabricates the
    // attestation leaf with notBefore=epoch-0, which the EnrollVerifier flags — see
    // verifier/EnrollVerifier 'attestation leaf not fabricated').
    {
        constexpr int kKsuMagic = 0xDEADBEEF;
        constexpr int kKsuCmdGetVersion = 2;
        int ksuVersion = 0;
        prctl(kKsuMagic, kKsuCmdGetVersion, reinterpret_cast<unsigned long>(&ksuVersion), 0, 0);
        if (ksuVersion > 0) {
            recs.push_back(record("kernelsu_present", "CRITICAL",
                                  "KernelSU kernel-level root detected via its magic prctl handler",
                                  "ksu_version=" + std::to_string(ksuVersion)));
        }
    }

    return recs;
}

}  // namespace dicore
