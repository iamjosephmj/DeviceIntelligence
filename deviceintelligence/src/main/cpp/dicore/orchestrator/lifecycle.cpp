#include "dicore/orchestrator/lifecycle.h"

#include "dicore/platform/string_gate.h"

#include "dicore/orchestrator/custody_wd.h"

// device-intelligence-lab: detection-only. The continuous kill-on-late-CRITICAL
// re-sweep daemon has been removed with the rest of the enforcement subsystem.
// A caller that wants fresh results simply invokes the single verdict entry
// point again. on_clean_device() now only publishes the string-unlock secret.
namespace dicore {

void on_clean_device() {
    // Publish the string-unlock secret U so the gated key entry can produce
    // consumer-string keys. Independent of any enforcement.
    string_gate_publish();
    // Latch the custody watchdog's clean-sweep bit: from here the forked child
    // starts releasing the NativeBridge.g unlock half (2 MAC-verified bytes per beat).
    custody_wd_note_clean_sweep();
}

}  // namespace dicore
