#include "module.h"

#include "../log.h"
#include "baseline.h"
#include "caller_verify.h"
#include "got_verify.h"
#include "range_map.h"
#include "text_verify.h"

namespace dicore::native_integrity {

void initialize(JNIEnv* /*env*/) {
    // G1 — range map is the prerequisite for every later layer.
    const size_t total = initialize_ranges();
    if (total == 0) {
        RLOGW("native_integrity: G1 init: range scan returned 0 entries");
    }
    // G3/G7 trust baseline — must run AFTER initialize_ranges
    // so libdicore's loader path is available for the app-lib
    // dir derivation, but BEFORE any user code (or attacker)
    // gets a chance to dlopen new libraries. The baseline is
    // captured exactly once and read-only thereafter; later
    // scans treat anything in this snapshot as trusted, which
    // is what makes G3/G7 self-adapting to new OEM partitions
    // and renamed kernel labels without code updates.
    const size_t baseline_total = initialize_baseline();
    if (baseline_total == 0) {
        RLOGW("native_integrity: G3/G7 baseline captured 0 entries");
    }
    // G2 — `.text` snapshot. Depends on the range map having
    // located libdicore's RX segment; safe no-op otherwise.
    initialize_text_verify();
    // G4 — GOT snapshot. Depends on the range map (libdicore
    // base + path); safe no-op if either is unavailable.
    initialize_got_verify();
    // G7 — JNI return-address verification. Arms the macro
    // exposed via `caller_verify_macro.h`; depends on libart's
    // RX range from the range map.
    initialize_caller_verify();
}

uint32_t probe() {
    return kProbeAlive;
}

}  // namespace dicore::native_integrity
