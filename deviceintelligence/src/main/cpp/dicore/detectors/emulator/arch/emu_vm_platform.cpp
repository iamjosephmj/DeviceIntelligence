// emu_vm_platform.cpp — INTEL_0048 (arm64_vm_platform): arm64 tier-2 probe
// for hardware-virtualized / full-system-emulated environments.
//
// Why: ARM KVM passes the host MIDR through, so there is no CPUID-style
// architectural tell on ARM (INTEL_0033 is x86-silicon-only). What leaks
// instead is the PLATFORM:
//   - /proc/device-tree model + compatible: QEMU machines report
//     "linux,dummy-virt" / "QEMU ...", cuttlefish reports its board,
//     goldfish/ranchu report ranchu. Real devices report the SoC board.
//   - /dev/qemu_pipe: the goldfish host-guest pipe device. Real hardware
//     has no such node; open(O_RDWR) succeeding is already strong.
//
// Every check fails open: unreadable files or a missing device contribute
// nothing. arm64-only by construction; other ABIs contribute nothing.
// Markers are classified by the pure header (host-tested); this TU is the
// thin IO wrapper.

#include "dicore/detectors/emulator/arch/emu_vm_markers.h"
#include "dicore/platform/obf.h"
#include "dicore/platform/syscalls.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__aarch64__)

namespace dicore {

namespace {

constexpr int kAtFdcwd = -100;

// Reads a small sysfs/procfs file fully into a fixed buffer. Returns the
// byte count, or -1 on any failure (missing file, permission, truncation).
ssize_t read_small_file(const char* path, char* buf, size_t cap) {
    int err = 0;
    const int fd = dicore::sys::raw_openat(kAtFdcwd, path, 0 /*O_RDONLY*/, 0, &err);
    if (fd < 0) return -1;
    const ssize_t n = dicore::sys::raw_read_full(fd, buf, cap - 1, &err);
    dicore::sys::raw_close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return n;
}

}  // namespace

std::vector<std::string> emu_vm_platform_records() {
    char buf[512];
    uint32_t flags = 0;

    // device-tree model + compatible (the compatible blob is
    // NUL-separated; byte scanning handles that)
    ssize_t n = read_small_file("/proc/device-tree/model", buf, sizeof(buf));
    if (n > 0) flags |= dicore::vmplat::scan_markers(buf, (size_t)n);
    n = read_small_file("/proc/device-tree/compatible", buf, sizeof(buf));
    if (n > 0) flags |= dicore::vmplat::scan_markers(buf, (size_t)n);

    // goldfish pipe device: open(O_RDWR) alone is the probe — real
    // hardware has no /dev/qemu_pipe node.
    int err = 0;
    const int qfd = dicore::sys::raw_openat(kAtFdcwd, "/dev/qemu_pipe", 2 /*O_RDWR*/, 0, &err);
    const bool qemu_pipe = qfd >= 0;
    if (qfd >= 0) dicore::sys::raw_close(qfd);
    if (qemu_pipe) flags |= dicore::vmplat::kMarkQemu;

    if (!dicore::vmplat::any_marker(flags)) return {};

    std::string r = "arm64_vm_platform";
    r += '\x1f';
    r += "CRITICAL";
    r += '\x1f';
    r += "flags=";
    char num[16];
    std::snprintf(num, sizeof(num), "%u", flags);
    r += num;
    if (flags & dicore::vmplat::kMarkQemu) r += "|qemu_pipe=1";
    if (flags & dicore::vmplat::kMarkGoldfish) r += "|goldfish=1";
    if (flags & dicore::vmplat::kMarkCrosvm) r += "|crosvm=1";
    if (flags & dicore::vmplat::kMarkCuttlefish) r += "|cuttlefish=1";
    if (flags & dicore::vmplat::kMarkDummyVirt) r += "|dummy_virt=1";
    return {r};
}

}  // namespace dicore

#else  // !__aarch64__

#include <string>
#include <vector>

namespace dicore {

// The arm64 platform probes read arm64 device-tree paths and the goldfish
// pipe device — on every other ABI they contribute nothing.
std::vector<std::string> emu_vm_platform_records() {
    return {};
}

}  // namespace dicore

#endif  // __aarch64__
