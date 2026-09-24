#pragma once

#include <cstdint>

// Minimal custody watchdog — the availability half of the anti-clone gate.
//
// A forked, pure-native child inherits a SipHash key (seeded from /dev/urandom
// BEFORE the fork) and holds a 16-byte "custody half" derived from that key and
// its own pid — material that exists nowhere else in the process, and nothing a
// repackage can ship. The child releases 2 bytes per MAC-verified CLEAN verdict
// over the socketpair; the parent's beat loop verifies each chunk MAC and
// accumulates the half in the PROT_NONE custody page (enforce/custody.cpp).
// string_gate_wait() blocks until all 8 chunks have landed, so NativeBridge.g cannot
// produce keys unless a genuine forked child of a genuinely-clean sweep is
// alive and beating. This is deliberately DETECTION-ADJACENT AVAILABILITY, not
// enforcement: a tampered process just never assembles the gate (locked UI);
// nothing is killed here (the enforcement machinery was removed with the lab's
// detection-only stance — see the PR hydraRaSp#11 history for why the kill
// half is a project of its own).
//
// Fail-open semantics: if fork/socketpair fail the child simply never exists
// and NativeBridge.g blocks (degraded UX, never a crash); respawns keep the SAME
// pre-fork key, so a respawned child re-releases the remaining chunks.
namespace dicore {

// Idempotent. Seeds the key, forks the first child, starts the beat + respawn
// threads. Call once at the top of the sweep funnel (dicore_verdict) so the
// child is alive while the startup sweep runs.
void custody_wd_init();

// Sticky: the sweep completed clean at least once (on_clean_device path).
// Chunks are only released on verdicts that carry this bit.
void custody_wd_note_clean_sweep();

// Sticky: a sweep counted a CRITICAL. The child stops releasing chunks.
void custody_wd_note_critical();

#if DICORE_WD_TEST
// TEST-ONLY (host tests, compiled with -DDICORE_WD_TEST=1): shrink the beat
// period so the 8-chunk release finishes in milliseconds. Never defined in
// release builds (same gate class as the retired wdtest property harness).
void custody_wd_set_beat_period_ms_for_test(int ms);
#endif

}  // namespace dicore
