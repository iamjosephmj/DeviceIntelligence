#include "dicore/orchestrator/custody_wd.h"

#include "dicore/enforce/custody.h"
#include "dicore/crypto/siphash.h"

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <ctime>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <atomic>

// Minimal custody watchdog (see custody_wd.h). Protocol on the SEQPACKET
// socketpair (parent <-> forked child):
//   parent -> child: 'C' + u64 nonce                     = challenge
//   child  -> parent: 'R' + u64 resp + u64 nonce_c       = SipHash(key, nonce)
//                                                          + fresh child nonce
//   parent -> child: 'V' + u64 nonce_c + u8 status + u64 mac
//            mac = SipHash(key, nonce_c || status)       = authenticated verdict
//   child  -> parent: 'H' + u8 chunk + b0 + b1 + u64 cmac
//            cmac = SipHash(key, nonce_c || chunk || b0 || b1)  = custody release
//
// Only the true fork child holds the key, so an externally-launched stub cannot
// answer challenges, and a hooked in-process sender cannot forge verdicts or
// chunks. There are NO kill semantics anywhere in this file: every anomaly is
// handled by the child leaving (or a chunk not being released), which leaves
// NativeBridge.g blocked — degraded availability, never a crash.

namespace dicore {
namespace {

#ifndef DICORE_WD_TEST
#define DICORE_WD_TEST 0
#endif

constexpr char kChallenge  = 'C';
constexpr char kResponse   = 'R';
constexpr char kVerdict    = 'V';
constexpr char kHalfChunk  = 'H';
constexpr uint8_t kStatusOK           = 0;
constexpr uint8_t kStatusCondemned    = 1;   // bit 0 — a sweep counted a CRITICAL
constexpr uint8_t kStatusOrchestrated = 2;   // bit 1 — the clean sweep completed

constexpr int  kBeatTimeoutMs    = 800;   // parent: how long it waits for the 'R'
constexpr int  kChunkPollMs      = 50;    // parent: how long it waits for the 'H'
constexpr int  kRespTimeoutMs    = 500;   // child: SO_RCVTIMEO per poll
constexpr int  kOrchMaxMisses    = 30;    // verdicts that may report "not orchestrated"
                                          // before the child concludes the sweep will
                                          // never run and leaves (gate stays closed)
constexpr int  kForkRetryMs      = 30;

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
int      g_wd_fd  = -1;
pid_t    g_wd_pid = -1;
void*    g_key_page = nullptr;
size_t   g_key_pgsz = 0;
pthread_once_t g_once = PTHREAD_ONCE_INIT;

std::atomic<int> g_condemned{0};
std::atomic<int> g_orchestrated{0};

#if DICORE_WD_TEST
std::atomic<int> g_beat_period_ms{2000};
#else
constexpr int kBeatPeriodMs = 2000;
#endif

double monotonic_now() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// ---- fork-inherited SipHash key in a PROT_NONE page (seeded before fork) ----
bool key_alloc() {
    if (g_key_page) return true;
    g_key_pgsz = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    if (g_key_pgsz == 0) g_key_pgsz = 4096;
    void* p = mmap(nullptr, g_key_pgsz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { g_key_page = nullptr; return false; }
    memset(p, 0, g_key_pgsz);
    g_key_page = p;
    return true;
}
void key_write(const uint64_t k[2]) {
    if (!g_key_page) return;
    mprotect(g_key_page, g_key_pgsz, PROT_READ | PROT_WRITE);
    memcpy(g_key_page, k, 16);
    mprotect(g_key_page, g_key_pgsz, PROT_NONE);
}
void key_read(uint64_t out[2]) {
    out[0] = 0; out[1] = 0;
    if (!g_key_page) return;
    mprotect(g_key_page, g_key_pgsz, PROT_READ);
    memcpy(out, g_key_page, 16);
    mprotect(g_key_page, g_key_pgsz, PROT_NONE);
}

void seed_key() {
    uint64_t k[2] = {0, 0};
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t got = 0;
        auto* p = reinterpret_cast<uint8_t*>(k);
        while (got < sizeof(k)) {
            ssize_t r = read(fd, p + got, sizeof(k) - got);
            if (r <= 0) break;
            got += static_cast<size_t>(r);
        }
        close(fd);
    }
    if (k[0] == 0) k[0] = (uint64_t)(monotonic_now() * 1e9) ^ (uintptr_t)&k;
    if (k[1] == 0) k[1] = ~k[0] * 0x100000001B3ULL;
    key_alloc();
    key_write(k);
    k[0] = 0; k[1] = 0;
}

uint64_t response_for(uint64_t nonce) {
    uint8_t buf[8]; memcpy(buf, &nonce, 8);
    uint64_t k[2]; key_read(k);
    uint64_t r = crypto::siphash24(buf, sizeof(buf), k[0], k[1]);
    k[0] = 0; k[1] = 0;
    return r;
}

uint64_t verdict_mac(uint64_t nonce_c, uint8_t status) {
    uint8_t buf[8 + 1];
    memcpy(buf, &nonce_c, 8);
    buf[8] = status;
    uint64_t k[2]; key_read(k);
    uint64_t r = crypto::siphash24(buf, sizeof(buf), k[0], k[1]);
    k[0] = 0; k[1] = 0;
    return r;
}

// ---- watchdog child (pure native, no JVM/ART, no heap) ----
[[noreturn]] void child_loop(int fd, int /*generation*/) {
    // Post-fork COW: strip any signal handlers the parent's (possibly hooked)
    // context installed, so nothing intercepts the child's own operations.
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    // H1 custody: this child holds 16 bytes of the NativeBridge.g unlock half, derived
    // from the fork-inherited SipHash key — it exists nowhere else. Released
    // 2 bytes per MAC-verified clean verdict; killing this child before all
    // 8 chunks land means the gate can never assemble.
    uint64_t k[2]; key_read(k);
    uint8_t  custody_half[16];
    {
        uint8_t mix[16 + 8];
        memcpy(mix, &k[0], 8); memcpy(mix + 8, &k[1], 8);
        uint64_t pid64 = (uint64_t)getpid();
        memcpy(mix + 16, &pid64, 8);
        for (int i = 0; i < 16; ++i) custody_half[i] = mix[i] ^ mix[(i + 8) % 24];
    }
    k[0] = 0; k[1] = 0;
    int      custody_released  = 0;
    uint64_t my_nonce_c        = 0;
    bool     sent_r            = false;
    bool     orchestrated_seen = false;
    int      not_orch_beats    = 0;
    uint8_t  msg[64];

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = kRespTimeoutMs * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        ssize_t n = recv(fd, msg, sizeof(msg), 0);   // one whole datagram (SEQPACKET)
        if (n == 0) _exit(0);                        // socket closed: parent dying
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;  // no kill on silence
            _exit(0);                                // real error: parent gone
        }
        char type = static_cast<char>(msg[0]);

        if (type == kChallenge) {
            if (n < 1 + 8) continue;
            uint64_t nonce = 0; memcpy(&nonce, msg + 1, 8);
            uint64_t resp = response_for(nonce);
            my_nonce_c = (static_cast<uint64_t>(monotonic_now() * 1e6)) ^
                         reinterpret_cast<uintptr_t>(&nonce) ^
                         (static_cast<uint64_t>(getpid()) << 17);
            uint8_t out[1 + 8 + 8];
            out[0] = static_cast<uint8_t>(kResponse);
            memcpy(out + 1, &resp, 8);
            memcpy(out + 9, &my_nonce_c, 8);
            if (send(fd, out, sizeof(out), MSG_NOSIGNAL) != static_cast<ssize_t>(sizeof(out))) _exit(0);
            sent_r = true;
            continue;
        }

        if (type == kVerdict) {
            if (n < 1 + 8 + 1 + 8) continue;
            uint64_t vnonce = 0; memcpy(&vnonce, msg + 1, 8);
            if (!sent_r || vnonce != my_nonce_c) continue;   // stale: ignore, never fatal
            uint8_t  status = msg[9];
            uint64_t vmac = 0; memcpy(&vmac, msg + 10, 8);
            // A forged verdict (hooked sender lying "healthy") cannot carry this
            // MAC. On any MAC failure or a condemned status the child leaves —
            // the remaining custody chunks are never released, NativeBridge.g stays blocked.
            if (vmac != verdict_mac(my_nonce_c, status)) _exit(0);
            if (status & kStatusCondemned) _exit(0);
            if (!orchestrated_seen) {
                if (status & kStatusOrchestrated) {
                    orchestrated_seen = true;
                } else if (++not_orch_beats >= kOrchMaxMisses) {
                    _exit(0);   // sweep never ran; gate stays closed
                }
            }
            // Custody release: 2 bytes per MAC-verified clean verdict.
            if (!(status & kStatusCondemned) && orchestrated_seen && custody_released < 8) {
                uint8_t chunk = static_cast<uint8_t>(custody_released);
                uint8_t hmsg[1 + 1 + 2 + 8];
                hmsg[0] = static_cast<uint8_t>(kHalfChunk);
                hmsg[1] = chunk;
                hmsg[2] = custody_half[chunk * 2];
                hmsg[3] = custody_half[chunk * 2 + 1];
                uint8_t macbuf[8 + 1 + 2]; memcpy(macbuf, &my_nonce_c, 8);
                macbuf[8] = chunk; macbuf[9] = hmsg[2]; macbuf[10] = hmsg[3];
                uint64_t h[2]; key_read(h);
                uint64_t cmac = crypto::siphash24(macbuf, sizeof(macbuf), h[0], h[1]);
                h[0] = 0; h[1] = 0;
                memcpy(hmsg + 4, &cmac, 8);
                if (send(fd, hmsg, sizeof(hmsg), MSG_NOSIGNAL) == static_cast<ssize_t>(sizeof(hmsg))) {
                    ++custody_released;
                }
            }
            continue;
        }
        // unknown datagram type: ignore
    }
}

bool spawn_locked(int generation) {     // caller holds g_lock
    int sv[2];
    // SOCK_SEQPACKET: message-boundary-preserving, so a slow child cannot
    // desync the channel.
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return false; }
    if (pid == 0) { close(sv[0]); child_loop(sv[1], generation); }
    close(sv[1]);
    if (g_wd_fd >= 0) close(g_wd_fd);
    g_wd_fd = sv[0]; g_wd_pid = pid;
    return true;
}

bool beat_once() {
    pthread_mutex_lock(&g_lock);
    int fd = g_wd_fd; bool ok = false;
    if (fd >= 0) {
        // drop any late datagram from a prior slow beat (SEQPACKET: no desync)
        for (;;) { uint8_t b[64]; ssize_t r = recv(fd, b, sizeof(b), MSG_DONTWAIT); if (r <= 0) break; }
        uint64_t nonce = ((uint64_t)(monotonic_now() * 1e6)) ^ (uintptr_t)&fd;
        uint8_t chal[1 + 8]; chal[0] = static_cast<uint8_t>(kChallenge);
        memcpy(chal + 1, &nonce, 8);
        if (send(fd, chal, sizeof(chal), MSG_NOSIGNAL) == static_cast<ssize_t>(sizeof(chal))) {
            pollfd pfd { fd, POLLIN, 0 };
            if (poll(&pfd, 1, kBeatTimeoutMs) == 1 && (pfd.revents & POLLIN)) {
                uint8_t msg[64];
                ssize_t n = recv(fd, msg, sizeof(msg), 0);
                if (n >= static_cast<ssize_t>(1 + 8 + 8) && msg[0] == static_cast<uint8_t>(kResponse)) {
                    uint64_t resp = 0, nonce_c = 0;
                    memcpy(&resp, msg + 1, 8);
                    memcpy(&nonce_c, msg + 9, 8);
                    ok = (resp == response_for(nonce));
                    if (ok) {
                        uint8_t status = kStatusOK;
                        if (g_condemned.load(std::memory_order_acquire))    status |= kStatusCondemned;
                        if (g_orchestrated.load(std::memory_order_acquire)) status |= kStatusOrchestrated;
                        uint8_t vout[1 + 8 + 1 + 8];
                        vout[0] = static_cast<uint8_t>(kVerdict);
                        memcpy(vout + 1, &nonce_c, 8);
                        vout[9] = status;
                        uint64_t vmac = verdict_mac(nonce_c, status);
                        memcpy(vout + 10, &vmac, 8);
                        (void)send(fd, vout, sizeof(vout), MSG_NOSIGNAL);
                        // H1: drain the 'H' custody chunk the child sends in
                        // response to this clean verdict.
                        pollfd hfd { fd, POLLIN, 0 };
                        if (poll(&hfd, 1, kChunkPollMs) == 1 && (hfd.revents & POLLIN)) {
                            uint8_t hmsg[64];
                            ssize_t hn = recv(fd, hmsg, sizeof(hmsg), MSG_DONTWAIT);
                            if (hn >= 1 + 1 + 2 + 8 && hmsg[0] == static_cast<uint8_t>(kHalfChunk)) {
                                uint8_t  chunk = hmsg[1];
                                uint8_t  macbuf[8 + 1 + 2];
                                memcpy(macbuf, &nonce_c, 8);
                                macbuf[8] = chunk; macbuf[9] = hmsg[2]; macbuf[10] = hmsg[3];
                                uint64_t h[2]; key_read(h);
                                uint64_t expect = crypto::siphash24(macbuf, sizeof(macbuf), h[0], h[1]);
                                h[0] = 0; h[1] = 0;
                                uint64_t got = 0; memcpy(&got, hmsg + 4, 8);
                                if (chunk < 8 && got == expect) {
                                    custody_store_chunk(chunk, hmsg[2], hmsg[3]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

void* heartbeat_main(void*) {
    for (;;) {
#if DICORE_WD_TEST
        usleep(g_beat_period_ms.load(std::memory_order_relaxed) * 1000);
#else
        usleep(kBeatPeriodMs * 1000);
#endif
        (void)beat_once();   // a missed beat costs one chunk release; never fatal
    }
    return nullptr;
}

// Respawn monitor: a dead child (OEM reap, crash, hostile kill) is replaced
// with the SAME pre-fork key, so a respawned child re-releases the remaining
// chunks. No escalation — child death only delays the gate.
void* monitor_main(void*) {
    int generation = 0;
    unsigned backoffUs = 0;
    for (;;) {
        pthread_mutex_lock(&g_lock);
        pid_t pid = g_wd_pid;
        pthread_mutex_unlock(&g_lock);
        if (pid <= 0) return nullptr;
        int st = 0;
        waitpid_again:
        if (waitpid(pid, &st, 0) < 0) {
            if (errno == EINTR) goto waitpid_again;
            return nullptr;
        }
        if (backoffUs) usleep(backoffUs);
        backoffUs = backoffUs ? (backoffUs * 2 > 8000000u ? 8000000u : backoffUs * 2)
                              : 100000u;   // 0.1s -> ... -> 8s cap
        pthread_mutex_lock(&g_lock);
        bool ok = spawn_locked(++generation);
        pthread_mutex_unlock(&g_lock);
        if (ok) backoffUs = 0;
        else usleep(kForkRetryMs * 1000);
    }
}

void do_init() {
    custody_init();      // PROT_NONE page for custody state (before fork)
    seed_key();          // before fork: the child inherits the key
    pthread_mutex_lock(&g_lock);
    bool ok = spawn_locked(0);
    pthread_mutex_unlock(&g_lock);
    if (!ok) return;     // fail-open: NativeBridge.g simply stays blocked
    pthread_t t;
    if (pthread_create(&t, nullptr, monitor_main, nullptr) == 0) pthread_detach(t);
    if (pthread_create(&t, nullptr, heartbeat_main, nullptr) == 0) pthread_detach(t);
}

}  // namespace

void custody_wd_init() { pthread_once(&g_once, do_init); }

void custody_wd_note_clean_sweep() {
    custody_wd_init();
    g_orchestrated.store(1, std::memory_order_release);
}

void custody_wd_note_critical() {
    g_condemned.store(1, std::memory_order_release);
}

#if DICORE_WD_TEST
void custody_wd_set_beat_period_ms_for_test(int ms) {
    g_beat_period_ms.store(ms, std::memory_order_relaxed);
}
#endif

}  // namespace dicore
