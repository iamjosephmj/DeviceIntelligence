#pragma once

#include <cstdint>

// G-series, libc edition: detect inline hooks in libc's .text by comparing the
// live executable segment against the pristine on-disk libc.so (read via RAW
// syscalls, so a libc hook cannot serve a clean copy).
namespace dicore::native_integrity {

enum class LibcTextStatus : uint8_t {
    kUnavailable = 0,   // could not locate/open/parse/size-match -> fail-open
    kOk = 1,            // live .text == on-disk .text
    kHashMismatch = 2,  // live .text != on-disk .text -> inline hook in libc
};

const char* libc_text_status_name(LibcTextStatus s);

// Compare libc's live executable segment against the on-disk libc.so. Safe at
// startup and on the resweep. Fail-open -> kUnavailable.
LibcTextStatus scan_libc_text();

// Escalation helper: copy up to `n` PRISTINE on-disk libc bytes corresponding to a
// LIVE code address in libc's executable segment (raw-syscall read, so a libc hook
// cannot serve a clean copy). Used to confirm an inline-hook stub is a REAL
// modification (on-disk prologue differs) and to suppress a legit on-disk thunk.
// Returns true and fills out[0..n) on success; false (fail-open) otherwise.
bool libc_ondisk_bytes(uintptr_t live_addr, uint8_t* out, size_t n);

}  // namespace dicore::native_integrity
