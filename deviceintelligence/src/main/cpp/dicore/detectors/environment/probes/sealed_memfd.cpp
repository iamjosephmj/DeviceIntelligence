// INTEL_0028 — sealed anonymous memfd stimulus.
//
// Code loaded from a sealed memfd leaves a mapping with no file behind it that is
// nonetheless not ordinary anonymous memory. It is how an injector ships code
// without writing it to a path a provenance scan could name.
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
#include <dirent.h>

namespace dicore {

using env::append_field;
using env::read_proc_self_maps;
using env::extract_pathname;
using env::range_bounds;

std::vector<std::string> sealed_memfd_records() {
    std::vector<std::string> out;
    std::vector<std::string> exec_memfd;
    std::string maps;
    if (read_proc_self_maps(&maps)) {
        size_t pos = 0;
        while (pos < maps.size()) {
            size_t eol = maps.find('\n', pos);
            std::string line = maps.substr(pos, (eol == std::string::npos ? maps.size() : eol) - pos);
            pos = (eol == std::string::npos) ? maps.size() : eol + 1;
            size_t sp = line.find(' ');
            if (sp == std::string::npos || sp + 4 > line.size()) continue;
            if (line[sp + 3] != 'x') continue;                       // exec only
            std::string p = extract_pathname(line);
            if (p.rfind("/memfd:", 0) == 0) exec_memfd.push_back(p);
        }
    }
    if (exec_memfd.empty()) return out;                              // no exec memfd -> fast out
    DIR* d = opendir("/proc/self/fd");
    if (!d) return out;
    struct dirent* e; int emitted = 0;
    while ((e = readdir(d)) != nullptr && emitted < 8) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char lp[64]; std::snprintf(lp, sizeof lp, "/proc/self/fd/%s", e->d_name);
        char tgt[256] = {0}; ssize_t n = readlink(lp, tgt, sizeof tgt - 1);
        if (n <= 0) continue; tgt[n] = 0;
        if (!std::strstr(tgt, "/memfd:")) continue;
        int fd = atoi(e->d_name);
        int seals = fcntl(fd, F_GET_SEALS);
        if (!(seals > 0 && (seals & F_SEAL_WRITE) && (seals & F_SEAL_SEAL))) continue;  // sealed-write only
        bool exec = false;
        for (const auto& p : exec_memfd) if (p == tgt) { exec = true; break; }
        if (!exec) continue;
        std::string r = "sealed_exec_memfd";
        r = append_field(r, "CRITICAL");   // FP-free by construction (sealed+exec memfd; ordinary apps never map one)
        r = append_field(r, "sealed executable memfd mapped");
        std::string oname(tgt);
        size_t del = oname.find(" (deleted)");
        if (del != std::string::npos) oname.erase(del);   // parseAttrs is space-delimited
        r = append_field(r, "object=" + oname);
        char sbuf[32]; std::snprintf(sbuf, sizeof sbuf, "seals=%#x", seals);
        r = append_field(r, sbuf);
        out.push_back(r);
        ++emitted;
    }
    closedir(d);
    return out;
}

// The hook-framework maps findings as CRITICAL verdict records. scan_runtime_maps
// emits them at HIGH and only runtime_hooking_present() (boot-gated) ever read
// them, so a named/anon hook-framework mapping never reached the verdict. A
// mapped hook framework is proof-positive, so re-stamp CRITICAL and surface it.

}  // namespace dicore
