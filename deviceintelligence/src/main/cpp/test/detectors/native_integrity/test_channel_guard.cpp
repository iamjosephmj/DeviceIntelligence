// deviceintelligence/src/main/cpp/test/detectors/native_integrity/test_channel_guard.cpp
#include <cstdio>
#include <cstring>
#include "dicore/detectors/native_integrity/channel_guard.hpp"

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main() {
    using namespace dicore::channel_guard;
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    SeqState st; seq_init(st, key);
    uint64_t c1 = seq_next(st, key, "checkout");
    uint64_t c2 = seq_next(st, key, "checkout");
    CHECK(c1 == 1 && c2 == 2);
    // verify against the state after exactly c1 (simulate backend replay)
    SeqState backend; seq_init(backend, key);
    uint64_t b1 = seq_next(backend, key, "checkout");
    CHECK(b1 == c1);
    CHECK(std::memcmp(backend.mac_chain, st.mac_chain, 32) != 0); // ours advanced past
    // tamper: wrong label fails, right label passes
    uint8_t good[32]; std::memcpy(good, backend.mac_chain, 32);
    CHECK(seq_verify(backend, 1, key, "checkout", good) == true);
    CHECK(seq_verify(backend, 1, key, "payout",    good) == false);
    // replay: counter already consumed
    CHECK(seq_verify(backend, 1, key, "checkout", good) == false);
    // fresh-state wrong-label: the label must be what rejects, not the replay
    // guard (counter 1 is unconsumed in st2, wrong label checked first)
    SeqState st2; seq_init(st2, key);
    seq_next(st2, key, "checkout");
    uint8_t chain2[32]; std::memcpy(chain2, st2.mac_chain, 32);
    CHECK(seq_verify(st2, 1, key, "payout",   chain2) == false); // wrong label
    CHECK(seq_verify(st2, 1, key, "checkout", chain2) == true);  // right label
    // cross-channel divergence: same key + counter, different labels
    SeqState st3; seq_init(st3, key);
    seq_next(st3, key, "payout");
    CHECK(std::memcmp(st2.mac_chain, st3.mac_chain, 32) != 0);
    // rate guard: 5 calls per 1000ms
    RateGuard rg; rate_init(rg, 1000, 5);
    bool all_ok = true;
    for (int i = 0; i < 5; i++) all_ok = rate_allow(rg, 100 + i) && all_ok;
    CHECK(all_ok);
    CHECK(rate_allow(rg, 200) == false);          // 6th inside window
    CHECK(rate_allow(rg, 100 + 1000) == true);    // window slid
    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
