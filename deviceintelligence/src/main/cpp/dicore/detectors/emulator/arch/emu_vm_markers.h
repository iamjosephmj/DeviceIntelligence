#pragma once

// Pure marker classifier for the arm64 VM-platform probe (INTEL_0063).
// Scans a byte range (device-tree model/compatible strings are
// NUL-separated; scanning bytes handles that) for hypervisor-platform
// markers, case-insensitively. Host-testable: no OS dependencies.

#include <cstdint>
#include <cstring>

namespace dicore::vmplat {

constexpr uint32_t kMarkQemu = 1u << 0;          // "qemu"
constexpr uint32_t kMarkGoldfish = 1u << 1;      // "goldfish" / "ranchu"
constexpr uint32_t kMarkCrosvm = 1u << 2;        // "crosvm"
constexpr uint32_t kMarkCuttlefish = 1u << 3;    // "cuttlefish"
constexpr uint32_t kMarkDummyVirt = 1u << 4;     // "dummy-virt"

inline char lower_ascii(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

inline bool contains_ci(const char* s, size_t len, const char* m, size_t ml) {
    if (ml == 0 || len < ml) return false;
    for (size_t i = 0; i + ml <= len; ++i) {
        size_t j = 0;
        while (j < ml && lower_ascii(s[i + j]) == lower_ascii(m[j])) ++j;
        if (j == ml) return true;
    }
    return false;
}

inline uint32_t scan_markers(const char* s, size_t len) {
    if (!s) return 0;
    uint32_t f = 0;
    if (contains_ci(s, len, "qemu", 4)) f |= kMarkQemu;
    if (contains_ci(s, len, "goldfish", 8) || contains_ci(s, len, "ranchu", 6))
        f |= kMarkGoldfish;
    if (contains_ci(s, len, "crosvm", 6)) f |= kMarkCrosvm;
    if (contains_ci(s, len, "cuttlefish", 10)) f |= kMarkCuttlefish;
    if (contains_ci(s, len, "dummy-virt", 10)) f |= kMarkDummyVirt;
    return f;
}

inline bool any_marker(uint32_t flags) { return flags != 0; }

}  // namespace dicore::vmplat
