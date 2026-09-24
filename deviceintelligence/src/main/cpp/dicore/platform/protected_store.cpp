#include "dicore/platform/protected_store.h"

#include "dicore/crypto/sha256.h"
#include "dicore/platform/log.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <random>

namespace dicore {
namespace {
size_t os_page_size() {
  long ps = ::sysconf(_SC_PAGESIZE);
  return ps > 0 ? static_cast<size_t>(ps) : 4096;
}
void* map_rw(size_t sz) {
  void* p = ::mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
}
}  // namespace

bool ProtectedStore::init(size_t value_bytes) {
  if (values_ != nullptr) return true;
  page_size_ = os_page_size();
  size_t pages = (value_bytes + page_size_ - 1) / page_size_;
  if (pages == 0) pages = 1;
  region_bytes_ = pages * page_size_;

  values_ = map_rw(region_bytes_);
  if (values_ == nullptr) {
    RLOGE("protected_store: mmap value region failed errno=%d", errno);
    return false;
  }
  // Map a randomised number of throwaway spacer pages so the value and hash
  // regions aren't deterministically adjacent (intentionally leaked).
  std::mt19937_64 rng(static_cast<uint64_t>(::getpid()) * 0x9E3779B97F4A7C15ull);
  const int spacers = static_cast<int>(rng() % 8);
  for (int i = 0; i < spacers; ++i) (void)map_rw(page_size_);

  hash_ = map_rw(page_size_);
  if (hash_ == nullptr) {
    ::munmap(values_, region_bytes_);
    values_ = nullptr;
    RLOGE("protected_store: mmap hash page failed errno=%d", errno);
    return false;
  }
  std::memset(values_, 0, region_bytes_);
  std::memset(hash_, 0, page_size_);
  value_bytes_ = value_bytes;
  return true;
}

bool ProtectedStore::unprotect() {
  if (!ready()) return false;
  if (::mprotect(values_, region_bytes_, PROT_READ | PROT_WRITE) != 0) return false;
  if (::mprotect(hash_, page_size_, PROT_READ | PROT_WRITE) != 0) {
    ::mprotect(values_, region_bytes_, PROT_NONE);
    return false;
  }
  return true;
}

void ProtectedStore::reprotect() {
  if (!ready()) return;
  ::mprotect(values_, region_bytes_, PROT_NONE);
  ::mprotect(hash_, page_size_, PROT_NONE);
}

void ProtectedStore::rehash() {
  if (!ready()) return;
  uint8_t h[sha::kDigestLen];
  if (sha::sha256(values_, region_bytes_, h))
    std::memcpy(hash_, h, sha::kDigestLen);
}

void ProtectedStore::seal() {
  rehash();
  reprotect();
}

bool ProtectedStore::intact() {
  if (!ready()) return false;
  uint8_t h[sha::kDigestLen];
  if (!sha::sha256(values_, region_bytes_, h)) return true;  // can't verify -> fail open
  return std::memcmp(h, hash_, sha::kDigestLen) == 0;
}

}  // namespace dicore
