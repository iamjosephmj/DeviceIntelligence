// anon_exec.hpp
#pragma once
#include <cstddef>
#include <cstdint>
namespace dicore::anon_exec {
struct Finding {
    uint64_t start, end;
    char perms[5];
    bool memfd;
    char path[128];
};
// Parses /proc/self/maps text; fills executable-anon/memfd/deleted findings.
// Returns count written (<= cap). Pure; never reads files, never throws.
size_t classify(const char* maps_text, Finding* out, size_t cap);
}
