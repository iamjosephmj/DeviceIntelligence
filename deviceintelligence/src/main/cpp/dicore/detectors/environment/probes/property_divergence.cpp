// INTEL_0043 — system-property divergence.
//
// Asks for a property two ways and flags a disagreement. A prop spoofer hooks the
// convenient path and forgets the other one; the DISAGREEMENT is the finding, which
// is the same shape as the boot-state cross-check in the attestation family.
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

static void dicore_prop_cb(void* cookie, const char* /*name*/, const char* value, uint32_t /*serial*/) {
    char* out = static_cast<char*>(cookie);
    std::strncpy(out, value ? value : "", PROP_VALUE_MAX - 1);
}
std::vector<std::string> property_divergence_records() {
    std::vector<std::string> out;
    static const char* kBootKeys[] = {
        "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
        "ro.boot.veritymode", "ro.build.tags", "ro.debuggable", "ro.secure",
    };
    for (const char* key : kBootKeys) {
        const prop_info* pi = __system_property_find(key);
        if (!pi) continue;                                  // key absent -> no ground truth
        char via_get[PROP_VALUE_MAX] = {0};
        __system_property_get(key, via_get);                // libc legacy path (maybe hooked)
        char via_cb[PROP_VALUE_MAX] = {0};
        __system_property_read_callback(pi, dicore_prop_cb, via_cb);   // property-area path (bypasses the hook)
        if (std::strcmp(via_get, via_cb) == 0) continue;    // agreement -> clean
        std::string r = "property_divergence";
        r = append_field(r, "CRITICAL");
        r = append_field(r, "property diverges from raw-svc read");
        r = append_field(r, "hooked_symbol=__system_property_get");
        r = append_field(r, std::string("key=") + key);
        r = append_field(r, std::string("get=") + via_get);
        r = append_field(r, std::string("area=") + via_cb);
        out.push_back(r);
        break;   // one proven lie is sufficient
    }
    return out;
}


}  // namespace dicore
