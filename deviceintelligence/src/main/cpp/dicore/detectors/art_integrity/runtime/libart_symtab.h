#pragma once

// In-memory ELF dynsym walker for libart.so.
//
// The Android linker namespace mechanism (API 24+) blocks app processes from
// dlsym'ing into libart.so — the call returns NULL even for symbols that ARE
// present in libart's .dynsym with default visibility (ART internals are not part
// of the NDK contract). To resolve such targets we bypass dlsym and walk libart's
// loaded ELF image directly: dl_iterate_phdr finds its load bias + program
// headers, we locate PT_DYNAMIC, pluck DT_SYMTAB/DT_STRTAB/DT_HASH|DT_GNU_HASH,
// compute the dynsym count from the hash table, and linear-scan by name. This
// bypass is well-known, ships in many production Android security tools, elevates
// no privilege, and only reads memory the linker already mapped read-only.
//
// Extracted from inline_prologue.cpp (F18 Vector D) so the libart-symbol-
// resolution responsibility is a reusable, independently-testable unit.

namespace dicore::art_integrity {

// Lazily locate libart's dynsym (dl_iterate_phdr on first call) and return whether
// it is ready to resolve symbols. Logs the discovered base/symtab once on success.
// Idempotent.
bool libart_symtab_ready();

// Runtime address of the libart symbol [name], or nullptr if the symtab isn't
// ready (call libart_symtab_ready() first) or the symbol isn't present.
const void* lookup_libart_symbol(const char* name);

}  // namespace dicore::art_integrity
