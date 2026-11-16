#pragma once

// Shared module-`.text` plumbing: locate a loaded module's executable segment
// in memory, and map the SAME segment from its pristine on-disk file.
//
// Extracted from libc_verify.cpp, whose comment anticipated this ("the same
// shape generalises to libart/linker by promoting this to a shared header when
// those detectors are added"). Both G8 (libc) and G10 (libart) use it.
//
// The on-disk read goes through raw syscalls, never libc stdio, so a libc hook
// cannot serve a doctored copy of the file it is being compared against.

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/** A module's live executable PT_LOAD segment, as the linker mapped it. */
struct LiveExecSeg {
    bool found = false;
    uintptr_t base = 0;       // dlpi_addr (load bias)
    uint64_t p_vaddr = 0;
    uint64_t p_filesz = 0;
    char name[512] = {};      // dlpi_name (the linker's path/soname)

    /** Runtime address of the first byte of the segment. */
    uintptr_t addr() const { return base + static_cast<uintptr_t>(p_vaddr); }
};

/**
 * Find the loaded module whose linker name ends with [suffix] (e.g. "libart.so")
 * and fill [out] with its first executable PT_LOAD segment. Returns false when
 * the module is absent or carries no PF_X segment — callers fail open.
 */
bool find_live_exec_seg(const char* suffix, LiveExecSeg* out);

/** An mmap'd on-disk file plus the location of its executable segment. */
struct DiskExecSeg {
    void* map = nullptr;      // whole-file read-only mapping; munmap via close_disk_exec_seg
    size_t map_len = 0;
    const uint8_t* text = nullptr;   // == map + file offset of the exec segment
    uint64_t filesz = 0;             // p_filesz of that segment
};

/**
 * Open [path] with raw syscalls, map it read-only, and locate its executable
 * segment. Returns false (nothing mapped) on any failure — malformed ELF,
 * unreadable path, no PF_X segment. On success the caller MUST pair this with
 * `close_disk_exec_seg`.
 */
bool open_disk_exec_seg(const char* path, DiskExecSeg* out);

/** Release a mapping obtained from `open_disk_exec_seg`. Safe on a zeroed struct. */
void close_disk_exec_seg(DiskExecSeg* seg);

}  // namespace dicore::native_integrity
