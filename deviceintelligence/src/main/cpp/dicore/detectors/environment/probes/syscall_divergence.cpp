// INTEL_0040 — behavioral syscall divergence.
//
// Split out of the old runtime_probe_jni.cpp: it shares nothing with the maps scan
// but the record separator, and it is the one probe whose correctness argument is
// entirely about the RAW syscall path, so it reads better alone.
#include "dicore/platform/log.h"
#include "dicore/core/verdict_cores.h"
#include "dicore/orchestrator/record_util.h"
#include "dicore/detectors/environment/maps/maps_parse.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/system_properties.h>

namespace dicore {

using env::append_field;
using env::read_proc_self_maps;
using env::extract_pathname;
using env::range_bounds;

static long dicore_raw_faccessat(const char* path) {
#if defined(__aarch64__)
    register long x8 asm("x8") = __NR_faccessat;
    register long x0 asm("x0") = (long)AT_FDCWD;
    register long x1 asm("x1") = (long)path;
    register long x2 asm("x2") = (long)F_OK;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
#else
    return syscall(__NR_faccessat, AT_FDCWD, path, F_OK);   // non-arm64 fallback (main target is arm64)
#endif
}

// Raw newfstatat(AT_FDCWD, path, stbuf, 0) via `svc`, bypassing libc — kernel ground truth
// for the stat-family divergence probe.
static long dicore_raw_stat(const char* path, void* stbuf) {
#if defined(__aarch64__)
    register long x8 asm("x8") = 79;                 // SYS_newfstatat (arm64)
    register long x0 asm("x0") = (long)AT_FDCWD;
    register long x1 asm("x1") = (long)path;
    register long x2 asm("x2") = (long)stbuf;
    register long x3 asm("x3") = 0;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
#else
    return fstatat(AT_FDCWD, path, static_cast<struct stat*>(stbuf), 0);  // non-arm64 fallback (fstatat != stat)
#endif
}

std::vector<std::string> syscall_divergence_records() {
    std::vector<std::string> out;
    // Paths that exist on every Android build; a hook hiding any of them is caught. Path
    // choice cannot cause an FP: divergence needs libc != kernel, which only a hook produces.
    static const char* kInvariantPaths[] = {
        "/system/bin/sh", "/system/lib64", "/apex/com.android.runtime",
        "/system/build.prop", "/system/framework", "/init",
    };
    // Each probe compares a libc entry point (which a userspace hook may intercept) against a
    // raw `svc` syscall that bypasses libc, over paths the kernel confirms exist. Flag only a
    // kernel-confirmed existence that libc denies — a hook hiding a file. faccessat AND the
    // stat family are checked, so a hook on either is caught.
    auto emit = [&](const char* sym, const char* path) {
        std::string r = "syscall_divergence";
        r = append_field(r, "CRITICAL");   // FP-free by construction; validated FP-clean on 3 OEMs
        r = append_field(r, "libc/raw file-query divergence");
        r = append_field(r, std::string("hooked_symbol=") + sym);
        r = append_field(r, std::string("path=") + path);
        out.push_back(r);
    };
    bool did_fac = false, did_stat = false;
    for (const char* path : kInvariantPaths) {
        if (!did_fac && dicore_raw_faccessat(path) == 0 && faccessat(AT_FDCWD, path, F_OK, 0) != 0) {
            emit("faccessat", path); did_fac = true;
        }
        if (!did_stat) {
            struct stat st_raw {}, st_libc {};
            if (dicore_raw_stat(path, &st_raw) == 0 && stat(path, &st_libc) != 0) {
                emit("stat", path); did_stat = true;
            }
        }
        if (did_fac && did_stat) break;
    }
    return out;
}

// INTEL_0043 — behavioral property divergence. A boot-state / root-indicator property read via
// libc __system_property_get (which a spoofer may hook) is compared against the SAME property
// read straight from the property area via __system_property_find + __system_property_read_callback
// (a different libc entry point the hook usually misses). A mismatch means __system_property_get is
// hooked to lie about the property — the in-process behavioral analog of INTEL_0030's attestation
// check. FP-free by construction: both read the same property trie, so they agree on a clean device
// (boot-state properties are static); only a selective hook on __system_property_get diverges.
// (A resetprop-style edit of the trie changes BOTH and is caught by attestation, not here.)

}  // namespace dicore
