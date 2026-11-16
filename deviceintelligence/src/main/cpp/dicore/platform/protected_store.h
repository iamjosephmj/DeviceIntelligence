#pragma once

#include <cstddef>
#include <cstdint>

// Self-protecting baseline storage shared by every snapshot-and-compare detector
// (G2 .text, G4 GOT, and the ART vectors). Two independently mmap'd regions kept
// at PROT_NONE between scans:
//   - a VALUE region (rounded up to whole pages) the detector fills with its
//     snapshot, and
//   - a HASH page holding SHA-256(value region).
// A randomised number of throwaway spacer pages is mapped between them so an
// attacker who locates one region can't deterministically find the other.
//
// Typical use:
//   store.init(bytes);                 // allocate, left writable
//   memcpy(store.values(), snap, n);   // write the snapshot
//   store.seal();                      // hash it and lock both regions
//   ...
//   if (store.unprotect()) {           // per scan
//     bool baseline_ok = store.intact();
//     // read store.values(), diff against live state
//     store.reprotect();
//   }
// An attacker who flips the pages RW to rewrite the snapshot is caught by the
// next intact() (the stored hash no longer matches).
namespace dicore {

class ProtectedStore {
public:
  // Allocate the value region (>= value_bytes) + hash page, zeroed and writable.
  // Idempotent; returns false only on mmap failure. No-op if already allocated.
  bool init(size_t value_bytes);
  bool ready() const { return values_ != nullptr && hash_ != nullptr; }

  void* values() { return values_; }
  template <class T> T* as() { return static_cast<T*>(values_); }
  size_t value_bytes() const { return value_bytes_; }

  bool unprotect();  // both regions -> RW; false on failure (regions stay locked)
  void reprotect();  // both regions -> PROT_NONE
  void rehash();     // (re)store SHA-256(value region) into the hash page; no protect change
  void seal();       // rehash() then reprotect() — the common init path
  bool intact();     // recompute SHA-256(value region) and compare to the hash page
                     // (call while unprotected). FAILS OPEN: if the SHA backend is
                     // unavailable it returns true (can't verify -> don't false-positive).

  // Raw page pointers, for a detector's own PROT_NONE self-audit of /proc/self/maps.
  const void* values_page() const { return values_; }
  const void* hash_page() const { return hash_; }

private:
  void* values_ = nullptr;
  void* hash_ = nullptr;
  size_t page_size_ = 0;
  size_t region_bytes_ = 0;  // value region rounded up to whole pages
  size_t value_bytes_ = 0;   // as requested
};

}  // namespace dicore
