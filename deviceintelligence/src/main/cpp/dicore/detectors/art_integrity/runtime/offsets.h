#pragma once

// F18 — ArtMethod field-offset table.
//
// The ArtMethod struct lives in `art/runtime/art_method.h` in
// AOSP. It's a private internal type — there is no Android API
// for reading its fields — so we hard-code the offset of the
// single field we care about (`entry_point_from_quick_compiled_code_`)
// per Android API level.
//
// Field history on 64-bit ART (the only architecture we ship; the
// AAR is ABI-filtered to arm64-v8a + x86_64):
//
// API 28-30 (Android 9 -> 11), `dex_code_item_offset_` still present:
//   ArtMethod {
//     GcRoot<mirror::Class> declaring_class_;     // 4 bytes
//     uint32_t access_flags_;                     // 4 bytes
//     uint32_t dex_code_item_offset_;             // 4 bytes
//     uint32_t dex_method_index_;                 // 4 bytes
//     union { uint16_t method_index_; uint16_t hotness_count_; };  // 2 bytes
//     uint16_t imt_index_;                        // 2 bytes
//                                                 // = 20 bytes header (0x14)
//     // Padding to 8-byte alignment for PtrSizedFields:
//                                                 // = 24 bytes after pad (0x18)
//     void* data_;                                // 8 bytes -> at 0x18
//     void* entry_point_from_quick_compiled_code_;// 8 bytes -> at 0x20
//   }
//   sizeof = 0x28
//
// API 31-36 (Android 12 -> 16), `dex_code_item_offset_` removed:
//   ArtMethod {
//     GcRoot<mirror::Class> declaring_class_;     // 4 bytes
//     uint32_t access_flags_;                     // 4 bytes
//     uint32_t dex_method_index_;                 // 4 bytes
//     union { uint16_t method_index_; uint16_t hotness_count_; };  // 2 bytes
//     uint16_t imt_index_;                        // 2 bytes
//                                                 // = 16 bytes header (0x10)
//     // Already 8-byte aligned; no padding.
//     void* data_;                                // 8 bytes -> at 0x10
//     void* entry_point_from_quick_compiled_code_;// 8 bytes -> at 0x18
//   }
//   sizeof = 0x20
//
// Empirical confirmation across both layouts:
//  - Pixel 6 Pro / Pixel 9 Pro, API 36: reading 0x20 yields the
//    *next* ArtMethod's `declaring_class_` (low-32-bit GcRoot
//    value, identical for sibling methods of the same class).
//    0x18 yields a libart-RX pointer.
//  - Huawei HwART / EMUI 12, API 31: same pattern as Pixel API
//    36 — confirms the smaller layout is in use on Android 12,
//    not just Android 13+. AOSP CL 1810420 ("ART: Remove
//    ArtMethod::dex_code_item_offset_") landed before the
//    Android 12 release, so this is the AOSP canonical layout
//    for S+, and OEMs (Huawei, Samsung) follow it.
//
// The per-API table is the central place to update when AOSP
// changes the layout. New Android versions land here first; every
// other F18 file consumes the offset through `entry_point_offset()`.

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

/**
 * Encoding kind of a JNI method ID, derivable from the raw value:
 *  - `POINTER`: low bit clear; the value is `(uintptr_t)ArtMethod*`.
 *  - `INDEX`: low bit set; the value is `(slot_index << 1) | 1` and
 *    the actual `ArtMethod*` lives in ART's per-class JNI ID table,
 *    reachable only via private `art::Runtime` APIs.
 *
 * ART picks INDEX encoding for some intrinsified static native
 * methods (currentTimeMillis, nanoTime, Math.abs(int) on the
 * devices we tested). Vector A's entry-point read must be skipped
 * for INDEX-encoded IDs because dereferencing them as pointers is
 * a wild memory read.
 */
enum class JniIdEncoding : uint8_t {
    POINTER = 1,
    INDEX = 2,
};

inline JniIdEncoding classify_jni_id(const void* jmethod_id) {
    return (reinterpret_cast<uintptr_t>(jmethod_id) & 0x1u) ? JniIdEncoding::INDEX
                                                            : JniIdEncoding::POINTER;
}

/**
 * Returns the byte offset of `entry_point_from_quick_compiled_code_`
 * inside `ArtMethod` for the given Android `sdk_int`. Returns
 * `kUnknownOffset` if [sdk_int] is below our floor (28) or if the
 * lookup table doesn't have an entry; callers must check for the
 * sentinel before using the offset.
 */
constexpr size_t kUnknownOffset = static_cast<size_t>(-1);
size_t entry_point_offset(int sdk_int);

/**
 * Returns the byte offset of the `data_` slot inside `ArtMethod`,
 * which for **native methods** holds `entry_point_from_jni_` —
 * the function pointer ART invokes when dispatching the JNI call.
 *
 * Frida-Java's `cls.method.implementation = ...` hook writes its
 * own bridge function pointer here (and additionally flips the
 * ACC_NATIVE bit for non-native methods); Vector E watches this
 * slot for drift on registry methods declared `native` in the JDK.
 *
 * Layout: `data_` is the first pointer of the `PtrSizedFields`
 * sub-struct, immediately preceding `entry_point_from_quick_compiled_code_`.
 * Offset is therefore always exactly 8 bytes lower than
 * [entry_point_offset] on every Android version we support.
 *
 * Returns `kUnknownOffset` when the API isn't covered.
 */
size_t jni_entry_offset(int sdk_int);

/**
 * Returns the byte offset of `access_flags_` inside `ArtMethod`,
 * which is a `uint32_t` bitfield containing modifier flags
 * (`ACC_PUBLIC`, `ACC_STATIC`, `ACC_NATIVE`, etc).
 *
 * Layout: stable at `offsetof(ArtMethod, access_flags_) == 0x04`
 * across every API in scope (28-36). The field sits immediately
 * after `GcRoot<mirror::Class> declaring_class_`, which is a
 * 4-byte managed-heap handle on every supported Android.
 *
 * Vector F watches the ACC_NATIVE bit (0x100) on every registry
 * slot — Frida-Java flips this bit ON when it hooks a non-native
 * method, and that's a binary, unambiguous tamper signal.
 */
constexpr size_t kAccessFlagsOffset = 0x04;
constexpr uint32_t kAccNative = 0x0100;
constexpr uint32_t kAccFastNative = 0x00080000;

/**
 * Highest Android API the table covers. Used to log a forward-
 * compat WARN when a future Android release calls in.
 */
constexpr int kMaxKnownApi = 36;

/**
 * Returns the entry pointer of an ArtMethod, given a pointer-
 * encoded jmethodID and the per-API offset. Returns nullptr if
 * the inputs are invalid or the read would obviously be out of
 * bounds (zero offset, null method).
 *
 * No memory protection here — callers must have already verified
 * the jmethodID is POINTER-encoded; reading at INDEX-encoded
 * pseudo-pointers is undefined behaviour.
 */
void* read_entry_point(const void* jmethod_id, size_t offset);

/**
 * Reads a 32-bit field at the given offset from the ArtMethod
 * pointer. Used by Vector F to read `access_flags_`. Returns 0
 * for INDEX-encoded jmethodIDs or null inputs.
 */
uint32_t read_u32_field(const void* jmethod_id, size_t offset);

}  // namespace dicore::art_integrity
