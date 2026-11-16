#pragma once

#include <cstddef>
#include <cstdint>

// Locating libdicore's Global Offset Table sections in the on-disk ELF — the
// parsing half of G4 GOT integrity (the scan half lives in got_verify.cpp).
// On modern Android the .so is mapped straight out of base.apk, so this also
// resolves the ELF's offset within the APK before parsing its section headers.
namespace dicore::native_integrity {

// One GOT / .got.plt section, mapped to its runtime address so the slots can be
// read live.
struct GotSection {
    uintptr_t addr_in_image;  // dlpi_addr + sh_addr (runtime address of the slots)
    size_t    bytes;
    size_t    slot_count;
    bool      valid;
};

// Resolve libdicore's on-disk ELF (an extracted .so, or inside base.apk), mmap
// it, and parse its `.got` / `.got.plt` into [got]/[got_plt] (runtime addresses
// via [base_addr]). Self-contained: opens, maps and unmaps the file. Returns
// false on any failure (path unknown, stripped ELF, mmap/parse failure).
bool locate_got_sections(uintptr_t base_addr, const char* compound_path,
                         GotSection* got, GotSection* got_plt);

}  // namespace dicore::native_integrity
