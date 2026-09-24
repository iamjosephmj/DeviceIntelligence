// channel_guard.hpp — INTEL_0058 scan-channel sequence MAC + rate guard.
// A scan channel chains SHA-256 over (session_key || prev_chain ||
// be64(counter) || label), rooted at the 32-byte session key. The key is
// folded into every step, so observing any chain value does not allow
// computing the next one without the key. A verifier holding the state
// replayed up to counter N verifies a reported (N, chain) pair exactly once
// (anti-replay via last_verified), comparing MACs in constant time.
#pragma once

#include <cstdint>

namespace dicore::channel_guard {

struct SeqState {
    uint64_t counter;                 // advances once per seq_next
    mutable uint64_t last_verified;   // consumed-marker; seq_verify mutates through const&
    uint8_t mac_chain[32];            // chain value for `counter` (== session key at init)
};

// Roots mac_chain at the session key; counter = 0, nothing verified yet.
void seq_init(SeqState& st, const uint8_t session_key[32]);

// Increments the counter and folds it into the chain:
//   mac_chain = SHA256(session_key || mac_chain || be64(counter) || scan_label)
// Returns the new counter.
uint64_t seq_next(SeqState& st, const uint8_t session_key[32], const char* scan_label);

// Accepts only reported_counter == st.counter that was not verified before,
// recomputes the chain value for that counter, and compares reported_mac in
// constant time. Marks the counter consumed on success.
bool seq_verify(const SeqState& st, uint64_t reported_counter,
                const uint8_t session_key[32], const char* scan_label,
                const uint8_t reported_mac[32]);

struct RateGuard {
    int64_t window_ms;
    int max_calls;
    int64_t t0;
    int count;
};

void rate_init(RateGuard& g, int window_ms, int max_calls);

// Sliding window: when now_ms - t0 >= window_ms the window resets
// (count = 0, t0 = now_ms). Returns false once max_calls is exhausted.
bool rate_allow(RateGuard& g, int64_t now_ms);

} // namespace dicore::channel_guard
