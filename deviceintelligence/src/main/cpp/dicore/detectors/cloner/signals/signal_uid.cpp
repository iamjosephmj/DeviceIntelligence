// signal_uid.cpp — the kernel-UID cloner signal. /proc/self/status reports the
// kernel-truth real UID; the facade compares it against Process.myUid(). A cloner
// can lie about either side but can't keep both in sync without root.

#include "dicore/detectors/cloner/cloner_probe.h"
#include "dicore/detectors/cloner/proc/cloner_proc.h"

#include <cstring>

namespace dicore::cloner {

using namespace detail;

int read_kernel_uid_from_status() {
    int parsed_uid = -1;

    bool ok = stream_lines("/proc/self/status",
        [&](const char* line, size_t line_len) -> bool {
            // Looking for: "Uid:\t<real>\t<eff>\t<saved>\t<fs>"
            constexpr const char* kPrefix = "Uid:";
            constexpr size_t kPrefixLen = 4;
            if (line_len < kPrefixLen + 1) return true;
            if (std::memcmp(line, kPrefix, kPrefixLen) != 0) return true;
            const char* p = line + kPrefixLen;
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p || !(*p >= '0' && *p <= '9')) return true;
            // Inline strtol (avoid pulling in a possibly-hooked libc strtol;
            // status's number format is trivial).
            int v = 0;
            while (*p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0');
                ++p;
            }
            parsed_uid = v;
            return false; // stop streaming
        });

    if (!ok) return -1;
    return parsed_uid;
}

}  // namespace dicore::cloner
