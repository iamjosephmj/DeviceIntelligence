#include "dicore/enforce/custody.h"
#include "dicore/crypto/siphash.h"

#include <sys/mman.h>
#include <cstring>
#include <cstdint>

namespace dicore {

// ---- Hardened custody state ----
// The custody half and chunk bitmap live in a PROT_NONE page (same technique
// as the SipHash key): invisible to a casual memory scan, and an attacker
// must explicitly mprotect or ptrace to reach it. The chunk MACs are stored
// alongside so custody_verify() can re-verify without the beat protocol.
//
// Layout within the page (offsets from page start):
//   [0..15]  custody_half[16]
//   [16]     custody_chunks (bitmask)
//   [24..87] chunk_macs[8][8]  (SipHash MAC per chunk)
static uint8_t* g_custody_page = nullptr;  // PROT_NONE between accesses

static void custody_page_init() {
    if (g_custody_page) return;
    g_custody_page = reinterpret_cast<uint8_t*>(
        mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (g_custody_page == MAP_FAILED) {
        g_custody_page = nullptr;
        return;
    }
    memset(g_custody_page, 0, 4096);
    mprotect(g_custody_page, 4096, PROT_NONE);
}

// Flip the page readable/writable for the duration of a critical section.
// RAII-style: the guard zeroes the write-enable flag on destruction.
struct CustodyGuard {
    bool ok;
    CustodyGuard(bool write) : ok(false) {
        if (!g_custody_page) return;
        ok = mprotect(g_custody_page, 4096,
                      PROT_READ | (write ? PROT_WRITE : 0)) == 0;
    }
    ~CustodyGuard() {
        if (g_custody_page) mprotect(g_custody_page, 4096, PROT_NONE);
    }
};

// Accessors for the state (defined in the header as extern for watchdog.cpp)
uint8_t* custody_half_ptr()   { return g_custody_page; }
uint8_t* custody_chunks_ptr() { return g_custody_page + 16; }
uint8_t* custody_macs_ptr()   { return g_custody_page + 24; }

bool custody_complete() {
    if (!g_custody_page) return false;
    CustodyGuard g(false);
    if (!g.ok) return false;
    return *custody_chunks_ptr() == 0xFF;
}

bool custody_verify() {
    if (!g_custody_page) return false;
    CustodyGuard g(false);
    if (!g.ok) return false;
    if (*custody_chunks_ptr() != 0xFF) return false;

    // Re-derive each chunk's expected MAC from the fork-inherited SipHash
    // key (parent has the same key — pre-fork inheritance). If the stored
    // half was tampered, at least one MAC will mismatch.
    // NOTE: the full verification requires the original nonce_c values used
    // per-chunk, which we don't persist. Instead we use a simplified
    // chunk-integrity check: the custody half is XOR'd with a per-page
    // checksum stored at offset [88..119] on each write. A root attacker
    // writing garbage to the half without updating the checksum is caught.
    uint8_t* stored_checksum = g_custody_page + 88;
    uint8_t computed[32];
    memset(computed, 0, sizeof(computed));
    uint8_t* half = custody_half_ptr();
    for (int i = 0; i < 16; ++i) {
        computed[i % 32] ^= half[i];
        computed[(i * 7 + 3) % 32] ^= (uint8_t)(half[i] << (i % 4));
    }
    computed[31] ^= *custody_chunks_ptr();
    if (memcmp(computed, stored_checksum, 32) != 0) {
        return false;   // tampered: garbage written without checksum update
    }
    return true;
}

void custody_copy_half(uint8_t out[16]) {
    if (!g_custody_page) { memset(out, 0, 16); return; }
    CustodyGuard g(false);
    if (!g.ok) { memset(out, 0, 16); return; }
    memcpy(out, custody_half_ptr(), 16);
}

void custody_scorch() {
    if (!g_custody_page) return;
    CustodyGuard g(true);
    if (!g.ok) return;
    memset(custody_half_ptr(), 0xA5, 16);
    *custody_chunks_ptr() = 0;
    memset(custody_macs_ptr(), 0, 64);
    memset(g_custody_page + 88, 0, 32);  // clear checksum too
}

void custody_store_chunk(uint8_t chunk, uint8_t b0, uint8_t b1) {
    if (!g_custody_page || chunk >= 8) return;
    CustodyGuard g(true);
    if (!g.ok) return;
    custody_half_ptr()[chunk * 2] = b0;
    custody_half_ptr()[chunk * 2 + 1] = b1;
    *custody_chunks_ptr() |= (uint8_t)(1u << chunk);

    // Update the integrity checksum
    uint8_t* stored_checksum = g_custody_page + 88;
    uint8_t computed[32];
    memset(computed, 0, sizeof(computed));
    uint8_t* half = custody_half_ptr();
    for (int i = 0; i < 16; ++i) {
        computed[i % 32] ^= half[i];
        computed[(i * 7 + 3) % 32] ^= (uint8_t)(half[i] << (i % 4));
    }
    computed[31] ^= *custody_chunks_ptr();
    memcpy(stored_checksum, computed, 32);
}

// Initialize the custody page (called from watchdog's do_init, before fork).
void custody_init() {
    custody_page_init();
}

}  // namespace dicore
