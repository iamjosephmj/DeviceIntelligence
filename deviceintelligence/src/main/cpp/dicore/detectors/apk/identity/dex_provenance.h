#pragma once

#include <string>
#include <vector>

namespace dicore {

// runtime.dex — dex-injection provenance. Enumerates every dex element in a
// REACHABLE class loader (op 13: the app loader chain + thread context loaders)
// and flags any whose source is not the app's own file-backed APK/splits:
//   - foreign_dex_loaded — a dex file loaded from an attacker-writable path
//     (/data/local/tmp, /sdcard, /storage/…). A genuine app never does this.
// (in_memory_dex_loaded was removed as false-positive prone: legit apps use
//  InMemoryDexClassLoader, so a null-path dex is not proof-positive.)
// System framework jars (/system, /apex) and the app's own /data/app dex + splits
// are never flagged. CRITICAL. Empty on a clean app / when the shim is
// unavailable (fail-open). A fully-detached loader that no thread references is
// out of reach here (that needs ART-internal enumeration — see FrameworkShim a15).
std::vector<std::string> dex_provenance_records();

}  // namespace dicore
