// F18 — ART integrity detector core. M0 placeholder; later milestones
// add the real vector implementations as separate translation units
// in this same directory:
//
//   M1   registry.cpp           frozen-method registry
//   M2   offsets.cpp            per-API ArtMethod offset table
//   M3   ranges.cpp             dl_iterate_phdr range resolver
//   M4-5 snapshot.cpp           Vector A snapshot+diff
//   M6   snapshot.cpp (extend)  PROT_NONE self-protection
//   M7   jni_env_table.cpp      Vector C snapshot
//   M8   inline_prologue.cpp    Vector D baseline+check
//
// Today the unit only carries the `probe()` liveness sentinel that
// proves the CMake wiring landed.

#include "art_integrity.h"

namespace dicore::art_integrity {

uint32_t probe() {
    return kProbeAlive;
}

}  // namespace dicore::art_integrity
