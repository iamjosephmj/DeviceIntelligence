#pragma once

#include <cstddef>
#include <cstdint>

// SipHash-2-4 — a tiny, dependency-free keyed MAC. Extracted from watchdog.cpp,
// where it authenticates the parent<->watchdog-child heartbeat: only a process
// holding the fork-inherited key can answer a challenge, so an externally-launched
// stub on the socket cannot impersonate the real watchdog.

namespace dicore::crypto {

uint64_t siphash24(const uint8_t* in, size_t len, uint64_t k0, uint64_t k1);

}  // namespace dicore::crypto
