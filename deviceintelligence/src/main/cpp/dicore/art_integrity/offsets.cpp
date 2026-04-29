#include "offsets.h"

#include "../log.h"

#include <cstring>

namespace dicore::art_integrity {

namespace {

// 64-bit ART layout of `entry_point_from_quick_compiled_code_`,
// per Android API. See header for the struct breakdown.
//
// API 28-36 all land at 0x20: the layout has been stable across
// every release we've shipped against. The per-API table exists
// so that the day Google moves the field we patch ONE row, not a
// scatter of magic numbers.
//
// If a row is missing for a future API, we fall back to the
// highest-known entry and log a WARN.
struct OffsetEntry {
    int api;
    size_t offset;
};

constexpr OffsetEntry kTable[] = {
    // API 28-32 (Android 9 -> 12L): dex_code_item_offset_ present
    // in the header, ArtMethod sizeof = 0x28, entry_point at 0x20.
    {28, 0x20},
    {29, 0x20},
    {30, 0x20},
    {31, 0x20},
    {32, 0x20},
    // API 33-36 (Android 13 -> 16): dex_code_item_offset_ removed,
    // ArtMethod sizeof = 0x20, entry_point at 0x18. Empirically
    // verified on Pixel 6 Pro (API 36) and Pixel 9 Pro (API 36):
    // reading 0x18 returns a pointer in libart's RX range, while
    // 0x20 reads into the next ArtMethod's declaring_class_.
    {33, 0x18},
    {34, 0x18},
    {35, 0x18},
    {36, 0x18},
};

constexpr size_t kTableLen = sizeof(kTable) / sizeof(kTable[0]);

}  // namespace

size_t entry_point_offset(int sdk_int) {
    if (sdk_int < kTable[0].api) {
        // Below our minimum-known API. Floor is 28 (matches the
        // library's minSdk); anything lower means the AAR was
        // shoehorned into an older app and F18 should silently
        // degrade.
        return kUnknownOffset;
    }
    for (size_t i = 0; i < kTableLen; ++i) {
        if (kTable[i].api == sdk_int) {
            return kTable[i].offset;
        }
    }
    // Not in the table: assume Android stayed source-compatible and
    // use the highest-known offset, but log so the engineer
    // notices when a new API ships.
    const OffsetEntry& latest = kTable[kTableLen - 1];
    RLOGW("F18 offsets: API %d not in table, falling back to API %d (offset 0x%zx)",
          sdk_int, latest.api, latest.offset);
    return latest.offset;
}

void* read_entry_point(const void* jmethod_id, size_t offset) {
    if (jmethod_id == nullptr || offset == kUnknownOffset) return nullptr;
    if (classify_jni_id(jmethod_id) != JniIdEncoding::POINTER) return nullptr;

    // Memcpy the 8-byte field rather than `*(void**)`. ART aligns
    // the struct on 8 bytes so a direct read would be safe in
    // practice, but memcpy keeps us correct under -fsanitize=alignment
    // and sidesteps any future packed-struct surprise.
    void* result = nullptr;
    const auto base = reinterpret_cast<const uint8_t*>(jmethod_id) + offset;
    std::memcpy(&result, base, sizeof(result));
    return result;
}

size_t jni_entry_offset(int sdk_int) {
    // `entry_point_from_jni_` (a.k.a. `data_`) sits exactly one
    // pointer slot below `entry_point_from_quick_compiled_code_`
    // on every supported API (see header for the full struct
    // breakdown). Derive instead of duplicating the per-API
    // table — keeps the two offsets locked in sync.
    const size_t quick = entry_point_offset(sdk_int);
    if (quick == kUnknownOffset || quick < sizeof(void*)) return kUnknownOffset;
    return quick - sizeof(void*);
}

uint32_t read_u32_field(const void* jmethod_id, size_t offset) {
    if (jmethod_id == nullptr) return 0;
    if (classify_jni_id(jmethod_id) != JniIdEncoding::POINTER) return 0;
    uint32_t result = 0;
    const auto base = reinterpret_cast<const uint8_t*>(jmethod_id) + offset;
    std::memcpy(&result, base, sizeof(result));
    return result;
}

}  // namespace dicore::art_integrity
