#pragma once

#include <cstdint>

// libc load-backing integrity (native_integrity G9): catches a consistent on-disk
// libc replacement (a bind-mount over /apex/...libc.so) that the .text-vs-disk
// check (libc_verify) is blind to, by checking libc's backing device against the
// read-only verified /apex/com.android.runtime mount.
namespace dicore::native_integrity {

enum class LibcBackingStatus : uint8_t {
    kUnavailable = 0,      // API<30 / parse failure / not found -> fail-open
    kOk = 1,              // libc backed by the genuine read-only apex
    kBackingMismatch = 2, // libc dev != apex dev (Signal A) -> bind-mount replacement
    kApexUntrusted = 3,   // apex mount not ro/ext4|erofs|f2fs//dev/block (Signal B)
};

const char* libc_backing_status_name(LibcBackingStatus s);

// Compare libc's backing device against the /apex/com.android.runtime mount and
// validate that mount's legitimacy. API>=30 only; fail-open -> kUnavailable. Safe
// at startup and on the resweep.
LibcBackingStatus scan_libc_backing();

}  // namespace dicore::native_integrity
