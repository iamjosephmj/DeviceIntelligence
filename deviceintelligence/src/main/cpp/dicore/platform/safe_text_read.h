#pragma once

#include <cstddef>

// Crash-safe reads of CODE memory.
//
// Android 10+ on arm64 maps platform libraries' .text EXECUTE-ONLY (built with
// `-Wl,--execute-only`, so PROT_EXEC without PROT_READ). Dereferencing an
// instruction byte there raises SIGSEGV with SEGV_ACCERR — "execute-only (no-read)
// memory access error; likely due to data in .text". That killed the process inside
// JNI_OnLoad on a Samsung Tab S5e (gts4lvwifi:10) the first time an XOM device ran
// the detectors, because vector D's prologue snapshot memcpy'd straight from libart.
//
// Any read of code we do not own must therefore go through here. The rule the rest
// of the codebase already follows for foreign memory (see maps_scan.cpp,
// trampoline.cpp, module_enrich.cpp) is: an unreadable page returns an ERROR, never
// a signal.

namespace dicore::platform {

/**
 * Reads [len] bytes of code at [addr] into [out].
 *
 * Returns false — never faults — when the region cannot be read.
 *
 * Two mechanisms, tried in order, because they differ in what they can see:
 *   1. `pread` on `/proc/self/mem`, which the kernel services with FOLL_FORCE and
 *      which therefore reads THROUGH an execute-only mapping.
 *   2. `process_vm_readv` on ourselves, which is faultless but does not force, so
 *      it may return EFAULT on the very XOM pages we care about.
 *
 * Order matters: (2) alone would stop the crash but leave every prologue read
 * failing on Android 10+, silently blinding the inline-hook detector. (1) is what
 * keeps it working; (2) remains as a fallback for environments where /proc/self/mem
 * is unavailable (a restricted mount namespace, a seccomp policy blocking openat).
 */
bool safe_read_code(const void* addr, void* out, size_t len);

}  // namespace dicore::platform
