#pragma once

namespace dicore {

// State transition taken once the startup sweep comes back clean (critical==0):
// publish the string-gate unlock secret, and — in enforcing builds — start the
// jittered RUNTIME_TAMPER resweep daemon so a hook/root/Frida attached AFTER
// startup is still caught and killed. Idempotent; the resweep starts at most once.
//
// Gated on critical==0, NOT merely on reaching here — on a bad device the kill
// path blocks ~1.5s before the process dies, and U must never unlock in that window.
void on_clean_device();

}  // namespace dicore
