#pragma once

// The /proc/self/maps walk itself: classify every mapping, characterize the
// suspicious ones, and emit ready-to-marshal finding records.
//
// One pass produces INTEL_0008 (a hook framework is mapped), INTEL_0009 (RWX regions,
// with their trampoline analysis attached) and INTEL_0035 (executable code from
// outside the legitimate roots). They share a pass because they read the same lines,
// and separating them would mean walking a 200-500 KB procfs file three times.

#include <string>
#include <vector>

namespace dicore {
namespace env {

// Walk the maps and append every finding. Read failure appends nothing.
void scan_runtime_maps(std::vector<std::string>& out);

}  // namespace env
}  // namespace dicore
