#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <sys/utsname.h>

namespace dicore::sys {

// Raw syscall wrappers. Each goes directly through `svc #0` (aarch64) or
// `syscall` (x86_64); they do not pass through any libc PLT entry, so an
// attacker who has hooked libc's `open`, `mmap`, `read`, etc. cannot observe
// or rewrite our reads.
//
// Errors are surfaced as -1 with a positive errno written into errno_out
// (we don't rely on the libc thread-local errno because that itself is
// reachable from libc-side hooks).

int    raw_openat(int dirfd, const char* path, int flags, int mode, int* errno_out);
int    raw_close(int fd);
// Single-shot read: raw_read_full below loops this. Exposed because the
// svc_io vtable (platform/svc_io.h) routes each read through its io backend
// so the shared read-file state machine is backend-injectable (host-tested).
ssize_t raw_read(int fd, void* buf, size_t count, int* errno_out);
ssize_t raw_write(int fd, const void* buf, size_t count, int* errno_out);
int    raw_getpid(int* errno_out);
ssize_t raw_read_full(int fd, void* buf, size_t count, int* errno_out);
off_t  raw_lseek(int fd, off_t offset, int whence, int* errno_out);
int    raw_fstat_size(int fd, off_t* out_size, int* errno_out);
void*  raw_mmap_readonly(size_t length, int fd, off_t offset, int* errno_out);
int    raw_munmap(void* addr, size_t length);

// Fault-safe read of our OWN address space: process_vm_readv(2) against self
// (raw syscall on the 64-bit ABIs). Unlike a C dereference, probing an
// UNMAPPED candidate address returns -1/EFAULT instead of raising SIGSEGV —
// own_image's base derivation probes candidate ELF-header addresses derived
// from maps arithmetic it has not otherwise verified, and a resolver that
// runs from every init_array ctor may never fault on a bad guess. Returns
// `len` on full success (partial copies are rejected), -1 on error.
ssize_t raw_self_read(const void* addr, size_t len, void* dst, int* errno_out);

// uname(2) by raw syscall. The kernel release feeds both the device fingerprint
// and INTEL_0019, so it must not be forgeable through a libc PLT hook.
//
// <sys/utsname.h> is included rather than forward-declared: a `struct utsname;`
// inside this namespace would declare dicore::sys::utsname, a DIFFERENT type
// that is ambiguous with ::utsname at every call site.
int    raw_uname(struct utsname* out, int* errno_out);

} // namespace dicore::sys
