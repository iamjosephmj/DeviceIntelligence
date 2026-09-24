#pragma once

#include <cstddef>
#include <cstdint>

// Pure, dependency-free ELF helper: find the first executable load segment.
// Used by libc_verify to locate libc's .text in an mmap'd on-disk image. Fully
// bounds-checked (runs on attacker-influenced file bytes), so it is host-testable
// and fuzzable in isolation.
namespace dicore::native_integrity {

// Find the first PT_LOAD segment with the PF_X (executable) flag in the ELF image
// [buf, len). On success writes its file offset, file size, and virtual address
// and returns true. Returns false on any malformed header or out-of-bounds field.
bool find_exec_segment(const uint8_t* buf, size_t len,
                       uint64_t* out_offset, uint64_t* out_filesz, uint64_t* out_vaddr);

}  // namespace dicore::native_integrity
