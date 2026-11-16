#include "dicore/orchestrator/record_util.h"

#include "dicore/orchestrator/orch_log.h"

#include <cstddef>

namespace dicore {

bool is_critical(const std::string& rec) {
    const auto f = decode_record(rec);
    return f.has_value() && is_critical(*f);
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
        const auto f = decode_record(r);
        if (f.has_value() && is_critical(*f)) {
            ++n;
            ORCH_LOG("orchestrate: CRITICAL %s/%s", detector, f->kind.c_str());
        }
    }
    return n;
}

}  // namespace dicore
