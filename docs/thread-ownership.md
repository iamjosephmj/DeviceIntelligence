# dicore thread-ownership map

Who owns which resource, and how threads talk to each other. The libuv-style
rule this codifies: **the sweep thread owns all verdict state; every other
thread is detached, stateless with respect to findings, and reports through
exactly one narrow channel.** No thread other than the sweep ever writes a
finding, a counter, or the token.

## The threads

| Thread / process | Created by | Owns | Talks to the rest via |
|---|---|---|---|
| Caller's thread (JNI entry: `NativeBridge.e` / `.c`) | the app | the entire sweep: verdict cores, `dicore_verdict` aggregation, token signing, the attested-session cache, the licence/`g_mon` monitor state | is the rest |
| Custody monitor | `pthread_create(monitor_main)` — `custody_wd.cpp`, detached | the beat-receive + chunk-MAC verification loop; the custody page accumulation | verifies MAC chunks off the socketpair; publishes only via the sticky `custody_wd_note_*` bits |
| Custody heartbeat | `pthread_create(heartbeat_main)` — `custody_wd.cpp`, detached | beat scheduling toward the forked child | writes only to the socketpair |
| Custody child (separate **process**, not a thread) | `fork()` — `custody_wd.cpp` | the SipHash key + its 16-byte custody half (exists nowhere else in the process) | releases 2 MAC'd bytes per clean verdict over the socketpair |
| Syscall smokescreen | `pthread_create(dicore_smoke_thread)` — `antidebug_verdict.cpp`, detached | nothing — fire-and-forget decoy syscalls | touches no shared verdict state by contract (every decoy is read-only / own-process / expected-denied) |

## JNI up-calls

`framework_shim.cpp` caches the `JavaVM` at `JNI_OnLoad` (`framework_shim_set_vm`).
Any thread that needs a framework value attaches its own JNIEnv around the call
(`AttachCurrentThread` — `framework_shim.cpp`) and reads a logic-free static off
`FrameworkShim`. Up-calls never throw: any failure returns an empty/false/`-1`
"unknown" sentinel. The sweep thread is the only caller on the hot path; the
custody and smokescreen threads make **no** up-calls at all.

## What was removed (do not reintroduce informally)

The enforcement-era continuous kill-on-late-CRITICAL re-sweep daemon is gone
(`lifecycle.cpp`); `dicore_verdict` runs only when the app drives it. A stale
comment in `framework_shim.h` still mentioned that thread — the map above is the
authoritative list. Adding a new background thread requires: (1) an entry here,
(2) a stated single reporting channel, (3) no findings/counter writes, (4) a
fail-open story for its own death.

## Reporting channels (complete list)

1. socketpair bytes, MAC-verified — custody child → monitor.
2. Sticky status bits `custody_wd_note_clean_sweep` / `_note_critical` — sweep
   thread → watchdog (one-way, never read back into the verdict).
3. The return value of `dicore_verdict` — sweep thread → app → backend.

Nothing else crosses a thread boundary. In particular there is no lock shared
between the smokescreen thread and any detector, and no detector reads custody
state except through the `string_gate_wait` availability gate documented in
`custody_wd.h`.
