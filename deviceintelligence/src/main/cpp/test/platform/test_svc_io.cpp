// Host substitution test for the direct-svc io layer (so-hardening B3).
//
// WHY: every sensitive file read (/proc/self/maps, app APK views) used to go
// through libc stdio (fopen/fgets) — a Frida-class attacker interposes those
// PLT entries and feeds the detectors a sanitized maps file, blinding the
// injected-code, JIT-range and inline-hook detectors wholesale. The fix routes
// the reads through raw syscalls. Raw `svc #0` cannot be usefully asserted
// better than libc on the host, so what this test pins is the substitution
// contract: the SAME read-file state machine (open → read-with-retry → close,
// partial reads, EOF, error propagation, cap) produces byte-identical results
// through BOTH injectable backends — the libc one and the raw-syscall one
// (which on an x86_64 host is the genuine `syscall` instruction, bypassing
// libc for real). aarch64 `svc` semantics get their on-device proof (Task 7).
//
// Build/run at the bottom.
#include "dicore/platform/svc_io.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>

using namespace dicore;

namespace {

// Real file fixture via mkstemp — no mocks: both backends read real bytes.
class TmpFile {
public:
    explicit TmpFile(const char* content, size_t len) {
        fd_ = ::mkstemp(path_);
        assert(fd_ >= 0);
        assert(::write(fd_, content, len) == (ssize_t)len);
        ::close(fd_);
    }
    ~TmpFile() { ::unlink(path_); }
    const char* path() const { return path_; }

private:
    char path_[32] = "/tmp/svc_io_test_XXXXXX";
    int fd_ = -1;
};

// Partial-read backend: same libc open/close, but each read() call returns at
// most ONE byte. This is the deterministic partial-read injector: if the state
// machine ever trusts a short read instead of retrying, content comes back
// truncated.
ssize_t one_byte_read(int fd, void* buf, size_t) { return ::read(fd, buf, 1); }

// ---- exists() vtable-injection fixtures ----------------------------------
// (a) open always fails → the probe must report not-exists.
int never_open(const char*) { return -1; }
void nop_close(int) {}

// (b) records every open + the last fd close saw — pins "a successful open
// is always closed, with the fd open handed back" (no fd leaks).
int g_last_fd = -12345;
int g_open_calls = 0;
int counting_open(const char* p) { ++g_open_calls; return ::open(p, O_RDONLY | O_CLOEXEC); }
void recording_close(int fd) { g_last_fd = fd; ::close(fd); }

}  // namespace

int main() {
    const char kText[] =
        "12c07000-12c08000 r-xp 00000000 fd:00 1234  /apex/com.android.art/lib64/libart.so\n"
        "7f8a000000-7f8a001000 rwxp 00000000 00:00 0  [anon:dalvik-DEX data]";

    // ---- read_file: full-content round-trip through every backend ----------
    TmpFile f(kText, sizeof(kText) - 1);
    const size_t kLen = sizeof(kText) - 1;

    std::string via_libc;
    assert(svc::read_file(svc::libc_io, f.path(), &via_libc));
    assert(via_libc.size() == kLen);
    assert(std::memcmp(via_libc.data(), kText, kLen) == 0);

    // Substitution: the svc backend (raw syscall on this host) must produce
    // byte-identical output for the same state machine.
    std::string via_svc;
    assert(svc::read_file(svc::svc_io, f.path(), &via_svc));
    assert(via_svc == via_libc);

    // Partial-read retry: a backend that hands out one byte at a time must
    // still yield the complete content.
    svc::Io byte_io = svc::libc_io;
    byte_io.read = one_byte_read;
    std::string via_dribble;
    assert(svc::read_file(byte_io, f.path(), &via_dribble));
    assert(via_dribble == via_libc);

    // ---- brief interface: open_ro / read_full / close_fd (svc path) --------
    int fd = svc::open_ro(f.path());
    assert(fd >= 0);
    std::string buf(kLen, '\0');
    assert(svc::read_full(fd, &buf[0], kLen) == (ssize_t)kLen);
    assert(buf == via_libc);
    svc::close_fd(fd);

    // read_full with a short buffer stops at EOF, reporting the byte count.
    fd = svc::open_ro(f.path());
    assert(fd >= 0);
    char head[16] = {};
    assert(svc::read_full(fd, head, sizeof(head)) == 16);
    assert(std::memcmp(head, kText, 16) == 0);
    svc::close_fd(fd);

    // ---- error paths -------------------------------------------------------
    // Nonexistent path fails (and clears out) through BOTH backends.
    std::string junk = "stale";
    assert(!svc::read_file(svc::libc_io, "/nonexistent/svc_io/path", &junk));
    assert(junk.empty());
    junk = "stale";
    assert(!svc::read_file(svc::svc_io, "/nonexistent/svc_io/path", &junk));
    assert(junk.empty());
    assert(svc::open_ro("/nonexistent/svc_io/path") < 0);

    // ---- exists: the existence probe root_probe's channels use -------------
    // Contract: open_rd-only probe — fd >= 0 means present (files AND
    // directories, matching the old access(F_OK) semantics for the magisk
    // dir paths); open failure means absent; the fd is always closed.
    assert(svc::exists(svc::libc_io, f.path()));
    assert(!svc::exists(svc::libc_io, "/nonexistent/svc_io/path"));
    assert(svc::exists(svc::svc_io, f.path()));
    assert(!svc::exists(svc::svc_io, "/nonexistent/svc_io/path"));
    assert(svc::exists(f.path()));   // production convenience (svc backend)
    assert(!svc::exists("/nonexistent/svc_io/path"));
    // Directory existence, like access(F_OK): the /data/adb/magisk-class
    // probes point at directories.
    assert(svc::exists(svc::libc_io, "/proc/self"));
    assert(svc::exists(svc::svc_io, "/proc/self"));

    // Vtable-injected backends pin the pure logic:
    // (a) open failure propagates as not-exists regardless of everything else.
    const svc::Io fail_io{never_open, one_byte_read, nop_close};
    assert(!svc::exists(fail_io, f.path()));
    assert(!svc::exists(fail_io, "/nonexistent/svc_io/path"));
    // (b) a successful open is always closed, with the fd that was handed
    // back — an existence probe must not leak fds (root_probe walks 15+
    // paths per scan).
    const svc::Io track_io{counting_open, one_byte_read, recording_close};
    const int before = g_open_calls;
    assert(svc::exists(track_io, f.path()));
    assert(g_open_calls == before + 1);
    assert(g_last_fd >= 0);   // close saw a real fd from open


    // A read error (directory fd → EISDIR) propagates as failure, not as a
    // short/empty "success" — detectors must see unreadable, not half-blind.
    std::string dir_content;
    assert(!svc::read_file(svc::libc_io, "/proc/self", &dir_content));
    assert(dir_content.empty());
    assert(!svc::read_file(svc::svc_io, "/proc/self", &dir_content));
    assert(dir_content.empty());

    // ---- cap enforcement ---------------------------------------------------
    // File exactly at the cap succeeds; beyond it fails rather than handing
    // the caller a silently truncated view of a sensitive file.
    assert(svc::read_file(svc::libc_io, f.path(), &via_libc, kLen));
    std::string capped;
    assert(!svc::read_file(svc::libc_io, f.path(), &capped, kLen - 1));
    assert(capped.empty());

    // Empty file reads as success with empty content.
    TmpFile empty("", 0);
    std::string empty_out = "x";
    assert(svc::read_file(svc::svc_io, empty.path(), &empty_out));
    assert(empty_out.empty());

    // ---- LineCursor: the fgets-replacement for converted call sites --------
    {
        const std::string maps = "a\nbb\nccc";  // final line unterminated
        svc::LineCursor cur(maps);
        std::string line;
        assert(cur.next(&line) && line == "a");
        assert(cur.next(&line) && line == "bb");
        assert(cur.next(&line) && line == "ccc");
        assert(!cur.next(&line));
    }
    {
        const std::string blanks = "\n\n";  // fgets yields bare newlines; cursor yields empty lines
        svc::LineCursor cur(blanks);
        std::string line;
        assert(cur.next(&line) && line.empty());
        assert(cur.next(&line) && line.empty());
        assert(!cur.next(&line));
    }
    {
        const std::string none;
        svc::LineCursor cur(none);
        std::string line;
        assert(!cur.next(&line));
    }
    {
        // Whole-file → lines round trip equals the file with terminators stripped.
        svc::LineCursor cur(via_svc);
        std::string line, reconstructed;
        size_t n_lines = 0;
        while (cur.next(&line)) {
            reconstructed += line;
            reconstructed += '\n';
            ++n_lines;
        }
        assert(n_lines == 2);
        assert(reconstructed == std::string(kText, kLen) + "\n");
        // ("ccc"-style final line was unterminated; re-adding '\n' per line
        // reconstructs the newline-terminated file.)
    }

    std::printf("test_svc_io OK\n");
    return 0;
}

/* Build/run:
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" "$CPP/test/platform/test_svc_io.cpp" \
       "$CPP/dicore/platform/svc_io.cpp" \
       "$CPP/dicore/platform/syscalls.cpp" \
       -o /tmp/test_svc_io && /tmp/test_svc_io */
