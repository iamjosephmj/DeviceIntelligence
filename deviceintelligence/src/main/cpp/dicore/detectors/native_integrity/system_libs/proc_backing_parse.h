#pragma once

#include <cstddef>
#include <cstdint>

// Pure, dependency-free parsers for two /proc lines, used by the libc load-backing
// detector. Host-testable in isolation (no JNI/syscalls). All inputs are
// attacker-influenceable /proc contents, so every read is bounds-checked.
namespace dicore::native_integrity {

// The parsed /apex/com.android.runtime mountinfo entry.
struct ApexMount {
    uint32_t major = 0;
    uint32_t minor = 0;
    bool ro = false;               // first option field is "ro"
    bool fstype_ok = false;        // fstype is ext4 / erofs / f2fs
    bool source_devblock = false;  // source path starts with /dev/block/
};

// If [line] (a /proc/self/maps line) is a "<...>/libc.so" mapping, parse its
// backing device (the maps dev field is HEX, e.g. "07:c0") into *major/*minor and
// return true. Returns false for any other mapping or a malformed line.
bool parse_maps_libc_dev(const char* line, size_t len, uint32_t* major, uint32_t* minor);

// If [line] (a /proc/self/mountinfo line) has mountpoint EXACTLY
// "/apex/com.android.runtime", fill *out (its dev field is DECIMAL, e.g. "7:192")
// and return true. Returns false for any other mountpoint or a malformed line.
bool parse_mountinfo_apex(const char* line, size_t len, ApexMount* out);

}  // namespace dicore::native_integrity
