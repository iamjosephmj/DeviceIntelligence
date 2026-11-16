#pragma once

// Turning a mapped address into provenance: which module is this, what does it link
// against, and which symbol does a GOT slot belong to.
//
// This is what makes a foreign mapping ACTIONABLE. "There is executable code from
// outside the legitimate roots" is a finding; "…and it is /data/adb/modules/<x>, and
// it links against a known hook library" is one a backend can act on. Split from the
// scan because the enrichment is the fiddly part — it walks ELF headers in the live
// process, and every read is bounds-checked because a hider controls those bytes.

#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/uio.h>

namespace dicore {
namespace env {

// Bounded read of a T from a live process address, via process_vm_readv so a bad
// address returns false instead of faulting. Every ELF walk below goes through this:
// the structures being parsed are in a foreign module a hider controls, so "fails
// open, never crashes" is the whole contract.
template <typename T> bool pvr(uintptr_t a, T* out) {
    struct iovec lo{out, sizeof(T)};
    struct iovec ro{reinterpret_cast<void*>(a), sizeof(T)};
    return process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)sizeof(T);
}

// Path of the mapping libdicore itself is loaded from.
std::string self_lib_path();

// Is this soname one of the known hook-framework libraries?
bool is_hook_soname(const std::string& so);

// Bounded read of a soname out of an ELF string table.
std::string safe_read_soname(uintptr_t straddr, size_t off, size_t strsz);

// Everything derivable from a module's load base: its DT_NEEDED list, whether any of
// them is a hook library, and so on — as FS-delimited detail fields.
std::string enrich_from_base(uintptr_t base);

// "/data/adb/modules/<id>/..." -> "<id>", else "".
std::string module_id_from_path(const std::string& pth);

// Which symbol a relocation slot belongs to, for naming a hooked GOT entry.
std::string resolve_reloc_symbol(uintptr_t base, uintptr_t slot_vaddr);

}  // namespace env
}  // namespace dicore
