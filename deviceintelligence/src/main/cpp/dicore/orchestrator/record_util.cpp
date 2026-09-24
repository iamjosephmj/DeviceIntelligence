#include "dicore/orchestrator/record_util.h"

#include "dicore/orchestrator/orch_log.h"

#include <cstddef>

namespace dicore {

bool is_critical(const std::string& rec) {
    size_t a = rec.find(kFS);
    if (a == std::string::npos) return false;
    size_t b = rec.find(kFS, a + 1);
    std::string sev = rec.substr(a + 1, (b == std::string::npos ? rec.size() : b) - (a + 1));
    return sev == "CRITICAL";
}

std::string field(const std::string& rec, int idx) {
    size_t pos = 0;
    for (int i = 0; ; ++i) {
        size_t fs = rec.find(kFS, pos);
        if (i == idx) return rec.substr(pos, (fs == std::string::npos ? rec.size() : fs) - pos);
        if (fs == std::string::npos) return "";
        pos = fs + 1;
    }
}

int count_critical(const char* detector, const std::vector<std::string>& recs) {
    int n = 0;
    for (const auto& r : recs) {
        if (is_critical(r)) {
            ++n;
            std::string kind = r.substr(0, r.find(kFS));
            ORCH_LOG("orchestrate: CRITICAL %s/%s", detector, kind.c_str());
        }
    }
    return n;
}

}  // namespace dicore
