// channel_guard.cpp — INTEL_0058 scan-channel sequence MAC + rate guard.
// Pure host-testable logic; the only crypto dependency is the vendored
// SHA-256 (dicore::sha), same backend every other crypto TU uses.
#include "dicore/detectors/native_integrity/channel_guard.hpp"

#include "dicore/crypto/sha256.h"

#include <cstring>

namespace dicore::channel_guard {
namespace {

// Scan labels are short internal channel names; anything longer is truncated
// to this cap (sender and verifier truncate identically, so verification
// stays consistent).
constexpr size_t kLabelCap = 128;

void put_be64(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
    }
}

// chain = SHA256(key || chain || be64(counter) || label). The session key is
// folded into every step: observing any chain value does not allow computing
// the next one without the key.
void chain_step(const uint8_t key[32], uint8_t chain[32], uint64_t counter, const char* label) {
    uint8_t buf[32 + 32 + 8 + kLabelCap];
    std::memcpy(buf, key, 32);
    std::memcpy(buf + 32, chain, 32);
    put_be64(buf + 64, counter);
    size_t label_len = 0;
    while (label[label_len] != '\0' && label_len < kLabelCap) {
        buf[72 + label_len] = static_cast<uint8_t>(label[label_len]);
        ++label_len;
    }
    dicore::sha::sha256(buf, 72 + label_len, chain);
}

// Constant-time 32-byte compare: XOR-fold, result == 0 means equal.
bool ct_eq_32(const uint8_t* a, const uint8_t* b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

} // namespace

void seq_init(SeqState& st, const uint8_t session_key[32]) {
    st.counter = 0;
    st.last_verified = 0;
    std::memcpy(st.mac_chain, session_key, 32);
}

uint64_t seq_next(SeqState& st, const uint8_t session_key[32], const char* scan_label) {
    ++st.counter;
    chain_step(session_key, st.mac_chain, st.counter, scan_label);
    return st.counter;
}

bool seq_verify(const SeqState& st, uint64_t reported_counter,
                const uint8_t session_key[32], const char* scan_label,
                const uint8_t reported_mac[32]) {
    // The report must match the state's position and be a fresh counter:
    // each counter verifies at most once (replay of an already-verified
    // counter is rejected). These gates run before any hashing so a bogus
    // huge counter cannot drive the recompute loop.
    if (reported_counter == 0 || reported_counter != st.counter) return false;
    if (st.last_verified != 0 && reported_counter <= st.last_verified) return false;

    // Recompute the chain value for reported_counter from the session seed.
    uint8_t expected[32];
    std::memcpy(expected, session_key, 32);
    for (uint64_t i = 1; i <= reported_counter; ++i) {
        chain_step(session_key, expected, i, scan_label);
    }

    if (ct_eq_32(reported_mac, expected)) {
        st.last_verified = reported_counter;  // consume
        return true;
    }
    return false;
}

void rate_init(RateGuard& g, int window_ms, int max_calls) {
    g.window_ms = window_ms;
    g.max_calls = max_calls;
    g.t0 = 0;
    g.count = 0;
}

bool rate_allow(RateGuard& g, int64_t now_ms) {
    if (now_ms - g.t0 >= g.window_ms) {
        g.count = 0;
        g.t0 = now_ms;
    }
    if (g.count >= g.max_calls) return false;
    ++g.count;
    return true;
}

} // namespace dicore::channel_guard
