// INTEL_0025 — a hook framework is mapped into this process.
//
// A thin reader over the shared maps scan rather than a second walk of the file:
// scan_runtime_maps() already classified everything, so this only filters.
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
#include "dicore/detectors/environment/maps/maps_scan.h"

namespace dicore {

using env::append_field;
using env::scan_runtime_maps;
using env::read_proc_self_maps;
using env::extract_pathname;
using env::range_bounds;

std::vector<std::string> hook_framework_records() {
    std::vector<std::string> raw, out;
    scan_runtime_maps(raw);
    const int api = android_get_device_api_level();
    const std::string from = std::string(1, kFS) + "HIGH" + std::string(1, kFS);
    const std::string to = std::string(1, kFS) + "CRITICAL" + std::string(1, kFS);
    for (auto& r : raw) {
        bool keep = false;
        bool restamp = true;   // most kept records escalate HIGH->CRITICAL
        if (r.rfind("hook_framework_present", 0) == 0) {
            keep = true;  // whole-token match on a hook-framework .so / anon name
        } else if (r.rfind("foreign_text_mapped", 0) == 0) {
            keep = true; restamp = false;  // provenance: injected code present, but a benign
                                          // root module can inject too -> stays HIGH (observe/step-up)
        } else if (r.rfind("got_ptr_hijack", 0) == 0) {
            keep = true;  // FP-free: legit lib pointer into injected foreign code
        } else if (r.rfind("libc_inline_hook", 0) == 0) {
            keep = true;  // FP-free: libc prologue rewritten to branch into foreign code
        } else if (r.rfind("libc_inline_stub", 0) == 0) {
            keep = true;  // opcode-shape inline hook; CRITICAL (restamp) — FP-clean on 3 OEMs (Pixel 6/9, Xiaomi)
        } else if (r.rfind("frida_memfd_jit_present", 0) == 0) {
            keep = true;  // rwxp /memfd:jit-cache — unambiguous Frida Gum signature
        } else if (r.rfind("rwx_memory_mapping", 0) == 0 && api >= 29) {
            // W^X: since API 29 (Android 10) an app cannot create a PROT_WRITE|
            // PROT_EXEC page (SELinux execmem neverallow; ART JIT uses a dual
            // RW/RX mapping), so a live RWX region is proof-positive of injection.
            // Skipped on API 28 where legacy single-mapping JIT could be RWX.
            keep = true;
        }
        if (!keep) continue;
        std::string s = r;
        if (restamp) {
            auto pos = s.find(from);
            if (pos != std::string::npos) s.replace(pos, from.size(), to);
        }
        out.push_back(std::move(s));
    }
    return out;
}


}  // namespace dicore
