---
title: Hook-detection CTF roadmap
status: living document
---

# Hook-detection CTF roadmap

This is the working document for **expanding hook / tampering
detection coverage** in DeviceIntelligence. The existing
`integrity.art` red-team harness (see `README.md` in this folder)
catches Vectors A/C/D/E/F plus the maps-based framework
signatures. This roadmap enumerates every technique that currently
**evades** that stack and turns each one into a numbered **flag**
the SDK should be able to capture.

The format is deliberate: each flag pairs a concrete attacker
behaviour with the detection signal we plan to ship and the
red-team script that will trip it. A flag is "captured" when a
clean baseline shows zero findings, the harness runs, and the
post-tamper `collect()` reports the expected finding kind. Same
contract as the existing Vectors A–F harnesses.

Flags are listed roughly in priority order. Flag 1 is the one
under active development.

## Coverage today (recap)

These are already shipped and captured by the existing harness.
Listed for orientation only — not part of this roadmap.

| Bucket               | Detector / file                                           | Frameworks caught                                                |
| -------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| ART entry-point      | `ArtIntegrityDetector` (Vectors A/C/D/E/F)                | LSPosed, EdXposed, YAHFA, Pine, SandHook, Whale, Frida-Java       |
| Native lib inventory | `native_integrity/lib_inventory.cpp`                      | Foreign `.so` injection, library-injection-style hooks            |
| GOT / `.text`        | `native_integrity/got_verify.cpp`, `text_verify.cpp`      | PLT/GOT rewriting, `.text` patching, inline native hooks          |
| Map signatures       | `MapsParser.kt`                                           | Frida-agent, Frida-gadget, libsubstrate, libxposed, libriru, libzygisk, libtaichi |
| Stack inspection     | `StackGuard`, `StackWatchdog`                             | Hooker frames on the call stack at JNI boundary                   |
| Tracer               | `RuntimeEnvironmentDetector` (`TracerPid`)                | Single-shot ptrace attach, JDWP debugger                          |
| Cloning              | `ClonerDetector`                                          | VirtualApp, Parallel Space, mount/UID mismatches                  |

Five independent ART vectors + native-side `.text`/GOT integrity
+ map signatures + stack inspection covers the bulk of the
"obvious" hooking surface. The flags below are the **non-obvious**
gaps.

---

## Flag 1 — Runtime DEX injection (detector + harness landed)

**Status: shipped, awaiting on-device capture.** Implementation
references:
- Helper: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/DexInjection.kt`
  (called from `RuntimeEnvironmentDetector.doLiveEvaluate`; **not** a
  separate detector — the findings ride on the `runtime.environment`
  wire-format ID alongside `hook_framework_present`,
  `rwx_memory_mapping`, etc.)
- Maps helper: `MapsParser.scanDalvikAnonRegions(...)` in the same package
- Five new finding kinds mapped to
  `IntegritySignal.HOOKING_FRAMEWORK_DETECTED` in
  `IntegritySignalMapper.KIND_TO_SIGNAL`:
  `dex_classloader_added`, `dex_path_outside_apk`,
  `dex_in_memory_loader_injected`, `dex_in_anonymous_mapping`,
  `unattributable_dex_at_baseline`
- Pure-JVM tests: `DexInjectionTest`, plus 6 new cases in
  `MapsParserTest` for the dalvik-anon scanner
- Red-team harnesses:
  `tools/red-team/dex-injection-inmemory.js` (channel b, Frida),
  `tools/red-team/dex-injection-disk.js` (channel a, Frida),
  `samples/lsposed-tester/.../DexInjectionHook` (real LSPosed module
  driving channels a + b — drops Frida from the loop)
- Payload generator: `tools/red-team/flag1-payload/` (Payload.java
  + build-payload.sh + checked-in payload.dex). The LSPosed module
  bakes the bytes into `Flag1Payload.kt` via the `bakeFlag1Payload`
  Gradle task at build time, so no `adb push` is required for the
  channel-b path.

**LSPosed harness timing model.** `handleLoadPackage` runs at app
classload time, BEFORE [DeviceIntelligenceInitProvider] gets a
chance to run its pre-warm collect. Injecting synchronously there
would land the new DEX in the chain before the detector's
first-evaluate snapshot, masking the signal as part of the
baseline. The harness avoids that by:

1. Posting a 2.5 s delayed task on the main thread (so
   Application.onCreate has finished installing ContentProviders).
2. Calling `DeviceIntelligence.collectBlocking(ctx)` once on a
   worker thread to lock in a known-clean baseline (this drives
   the `DexInjection` helper inside `runtime.environment` — it
   captures its first-call snapshot whether the prewarm has run
   or not).
3. Loading the baked DEX via `InMemoryDexClassLoader` (channel b)
   and, if `/data/local/tmp/flag1-payload.dex` is present, also
   via `DexClassLoader` (channel a).
4. Calling `collectBlocking` again and diffing the
   `runtime.environment` findings (filtered to the five
   `DexInjection`-emitted kinds). `FLAG CAPTURED` lands in
   `logcat -s DI-LSPDexHook` (or LSPosed's own log) when the
   post-tamper delta contains `dex_in_memory_loader_injected`,
   `dex_in_anonymous_mapping`, or `dex_path_outside_apk`.

**Three timing scenarios to validate on-device** (all using the
single `lsposed-tester` APK; flip whichever single entry you
want active for a clean signal):

| Scenario           | Active xposed_init entry        | Injection happens     | Expected detector behaviour                                     |
| ------------------ | ------------------------------- | --------------------- | ----------------------------------------------------------------- |
| Late (post-prewarm) | `DexInjectionHook`              | ~2.5 s after launch   | `FLAG CAPTURED` — channels (a) + (b) both see new state.        |
| Early (pre-baseline) | `EarlyDexInjectionHook`         | At handleLoadPackage  | LIKELY `FLAG NOT CAPTURED` — simulates Zygisk timing gap.       |
| Real Zygisk         | (separate Magisk module, TBD)   | At postAppSpecialize  | Same as Early; this is the production-realistic version.       |

**Why simulate Zygisk via early-LSPosed first?** LSPosed's
`handleLoadPackage` runs in the same lifecycle window as
Zygisk's `postAppSpecialize` — after the host classloader is
built, before `Application.onCreate`. Synchronous injection
there reproduces Zygisk's pre-baseline timing without requiring
a Magisk module flash + reboot cycle. If the Early scenario
captures the same gap a real Zygisk module would, we can fix the
detector first and only then verify against real Zygisk.

**Predicted detector gap (the thing the Early scenario tests —
captured and resolved as of 0.6.0).** The `DexInjection` helper
snapshots the loader chain on first scan — which is whenever the
prewarm coroutine first runs `runtime.environment`. If a foreign
DEX is in the chain BEFORE that snapshot, channel (a)'s diff
sees it as part of the clean baseline and never flags it.
Channel (b) has the same problem for the `[anon:dalvik-...]`
baseline. The fix shipped in 0.6.0: emit a derived
`unattributable_dex_at_baseline` finding (severity MEDIUM,
informational) whenever the FIRST observed snapshot already
contains a DEX element whose path is null or outside the APK
split set. Won't reach the Frida-style "clean baseline + dirty
post-tamper" deterministic capture, but gives backends a strong
signal to correlate on across many devices. Validated on Pixel
6 Pro / Android 16: the Early hook reliably trips
`unattributable_dex_at_baseline` on prewarm.


**Attacker behaviour**

Load arbitrary code into the running process **without** loading a
foreign `.so`, **without** patching any `ArtMethod`, and **without**
allocating an `RWX` page. Two real-world variants:

1. `InMemoryDexClassLoader(ByteBuffer, parent)` — DEX bytes never
   touch disk; loader registers a DEX cookie inside ART, sitting
   in the Java heap as ordinary `RW` memory.
2. `DexClassLoader(path, ...)` pointed at a payload dropped by a
   Zygisk or Magisk module under `/data/local/tmp/`,
   `/data/data/<other-pkg>/`, or any path that is not the app's
   own APK or dalvik-cache.

**Why current detection misses it**

| Layer                              | Why it stays quiet                                              |
| ---------------------------------- | ----------------------------------------------------------------- |
| `MapsParser`                       | No foreign `.so` mapped — no name to match.                       |
| `lib_inventory`                    | No native library load — manifest is unchanged.                   |
| ART vectors A/C/D/E/F              | Existing classes' `ArtMethod`s are untouched; payload runs as new methods on a new class. |
| RWX scan (`RuntimeEnvironmentDetector.kt:315`) | DEX bytes sit in `RW`, not `RWX`; ART's JIT cache is `RWX` but legitimately so. |
| `text_verify` / `got_verify`       | Native `.text` and GOT are unchanged.                             |
| `StackGuard`                       | Hooker is not on the stack at the JNI boundary; new code runs in its own frames. |

**Detection plan (three independent channels — any one fires →
finding emitted)**

- **(a) ClassLoader-chain diff (cheap, ~2–5 ms).** Walk every
  `BaseDexClassLoader` from `Context.classLoader` upward through
  `parent`. For each, reflect `pathList.dexElements`, then each
  element's `dexFile.mFileName` / `mCookie`. Snapshot at
  `JNI_OnLoad`. On every `collect()`, diff against the snapshot.
  Any **new** element, or any element whose path is not under
  `/data/app/<pkg>/`, `/data/dalvik-cache/`, or the APK split set
  declared by `PackageManager`, emits a finding.

- **(b) `/proc/self/maps` DEX-magic scan (medium, ~10–20 ms).**
  Reuse the existing maps walk. For each readable, non-system,
  non-APK mapping (especially `[anon:dalvik-...]`,
  `[anon:libc_malloc]`, plain `[anon]`), read the first 8 bytes and
  match against `dex\n035`, `dex\n037`, `dex\n038`, `dex\n039`,
  `cdex001`. Any DEX magic in a mapping not backed by an APK or
  dalvik-cache file emits a finding. Catches
  `InMemoryDexClassLoader` even when the ClassLoader chain is
  itself tampered with.

- **(c) ART ClassLinker enumeration (medium, JNI; version-gated).**
  Via JNI, snapshot the size of `ClassLinker::dex_caches_` at
  `JNI_OnLoad`. Recompare on demand. Growth without an
  attributable APK/system source = injection. Brittle across
  Android versions (offsets change), so behind a
  `Build.VERSION.SDK_INT` whitelist.

Combine (a)+(b) for high-confidence detection without root and
without ART-internals fragility; (c) is a third independent vector
on supported API levels.

**Finding kinds (proposed)**

| Kind                            | Severity | Source channel | Meaning                                                            |
| ------------------------------- | -------- | -------------- | -------------------------------------------------------------------- |
| `dex_classloader_added`         | HIGH     | (a)            | A new `DexClassLoader`/`PathClassLoader`/`InMemoryDexClassLoader` exists in the chain that was not present at `JNI_OnLoad`. |
| `dex_path_outside_apk`          | HIGH     | (a)            | A registered DEX path is outside the app's APK split set and dalvik-cache. |
| `dex_in_anonymous_mapping`      | HIGH     | (b)            | DEX/CDEX magic detected in a `[anon:*]` mapping not attributed to an APK file. |
| `dex_cache_count_grew`          | MEDIUM   | (c)            | ART `dex_caches_` grew vs `JNI_OnLoad` snapshot; no attributable source. |
| `dex_inspection_unsupported`    | INFO     | (c)            | API level / ART layout outside the supported range; (c) skipped on this device. |

Wire-name (as shipped in 0.6.0+): findings ride on
`runtime.environment` alongside the other process-wide
hook-detection signals (`hook_framework_present`,
`rwx_memory_mapping`, etc.). DEX injection is bytecode-level
hooking and conceptually belongs in the same bucket. Earlier
drafts of this document proposed a separate `runtime.dex`
detector ID; that was merged into `runtime.environment` for
taxonomy alignment.

**Red-team harness (planned)**

- `tools/red-team/dex-injection-inmemory.js` — Frida script that
  pre-warms the bridge, takes a clean `runtime.environment`
  baseline (filtered to DEX-injection-specific kinds), then uses
  `Java.use("dalvik.system.InMemoryDexClassLoader")` to
  `$new(...)` a tiny payload DEX (~50 bytes, one empty class)
  from a `ByteBuffer.wrap(bytes)`. Re-runs `collect()` and asserts
  `dex_in_anonymous_mapping` + `dex_classloader_added` fire.
- `tools/red-team/dex-injection-disk.js` — pushes a
  `payload.dex` to `/data/local/tmp/` and uses `DexClassLoader` to
  load it. Asserts `dex_path_outside_apk` + `dex_classloader_added`
  fire.
- A debug-only `:samples:minimal` toggle that performs the same
  injection from in-app code, so the flag can be captured **without
  Frida** on a non-rooted device. Useful for CI unit-style
  validation.

**Capture criteria**

A run captures Flag 1 when:

1. Clean dry-run shows zero DEX-injection-related findings in
   the `runtime.environment` detector report (filter the report's
   findings to the five `DexInjection`-emitted kinds).
2. Harness loads a foreign DEX.
3. Post-tamper `collect()` reports at least one of
   `dex_classloader_added`, `dex_path_outside_apk`, or
   `dex_in_anonymous_mapping` under `runtime.environment`.
4. Restoring/clearing the loader on a fresh process boot returns
   the dry-run to clean.

---

## Flag 2 — Newer hooking framework signatures (partially captured)

**Status: 5 of 8 frameworks shipped in 0.9.0; 3 deferred for
false-positive risk.** `MapsParser.HOOK_FRAMEWORK_SIGNATURES`
extended with the canonical names below.

| Framework        | Status        | Notes |
| ---------------- | ------------- | ----- |
| **Dobby**        | shipped 0.9.0 | `libdobby`, `dobby_bridge` — both signatures match. |
| **Whale**        | shipped 0.9.0 | `libwhale` — minimal legitimate-embed risk. |
| **YAHFA**        | shipped 0.9.0 | `libyahfa` — EdXposed/LSPosed ART-side backend. |
| **FastHook**     | shipped 0.9.0 | `libfasthook` — niche, mostly seen in game-modding kits. |
| **il2cpp-dumper** | shipped 0.9.0 | `libil2cppdumper`, `zygisk-il2cpp` — Zygisk module that dumps Unity IL2CPP game logic. |
| **ShadowHook**   | DEFERRED      | Bytedance ships `libshadowhook.so` IN their own apps (TikTok, Douyin, CapCut, Lemon8). Name-only detection would FP on every Bytedance install. Needs the embedded-vs-injected distinction (cross-reference against the consumer's build-time native-lib inventory) before this can ship. |
| **SandHook**     | DEFERRED      | Same problem — used as a backend by EdXposed but also by some legitimate game-cheat-prevention frameworks. |
| **Pine**         | DEFERRED      | Same problem — used as ART-hook backend by both attack tooling AND some legitimate frameworks. |

**Embedded-vs-injected distinction (the prerequisite for the
deferred three):** the build-time `Fingerprint` plugin already
captures the consumer app's full native-lib inventory under
`Fingerprint.expectedSoList`. The runtime side could be taught
to suppress `hook_framework_present` for any framework whose
library path is INSIDE the consumer's own APK split set. That
would make name-based detection safe to ship for ShadowHook /
SandHook / Pine — with the trade-off that an attacker who drops
their payload INSIDE the consumer's APK directory tree would
evade. For most consumer apps the trade-off is correct; for
SDK-distributed code it's harder. Tracked as a separate roadmap
item.

**Harness:** `tools/red-team/maps-newer-frameworks.js` — uses
Frida's `Memory.allocAndName` (or a `prctl(PR_SET_VMA_ANON_NAME)`
fallback) to label anonymous pages with each candidate signature,
runs `collect()`, asserts that the post-tamper
`runtime.environment` findings include `hook_framework_present`
with the expected `details.framework` value for all 5 shipped
frameworks. `FLAG CAPTURED` lands when every signature trips.

**Capture criteria** — Flag 2 is captured when:
1. Clean dry-run shows zero `hook_framework_present` findings for
   the 5 newly-added frameworks.
2. Harness allocates and names a page per candidate framework.
3. Post-tamper `collect()` reports `hook_framework_present` with
   `details.framework == <canonical name>` for ALL FIVE shipped
   frameworks (`dobby`, `whale`, `yahfa`, `fasthook`,
   `il2cpp_dumper`).

---

## Flag 3 — Shamiko / Magisk-hide property interception

**Attacker behaviour:** Shamiko (Magisk hider) intercepts
`__system_property_get` / `getprop` to spoof `ro.build.fingerprint`,
`ro.debuggable`, `ro.boot.verifiedbootstate`, etc.

**Why current detection misses it:** the existing
`RuntimeEnvironmentDetector` mismatch check
(`RuntimeEnvironmentDetector.kt:256`) catches inconsistencies
between Java-layer values, but a competent hider returns a
self-consistent clean-device tuple to every reader.

**Detection plan:**

- Read the same property via two paths and compare:
  native `__system_property_get` (JNI) vs reflected
  `SystemProperties.get(...)` vs `/system/build.prop` raw read.
  Divergence = interception.
- Time `__system_property_get` calls against a tight baseline
  captured at `JNI_OnLoad`. Latency outliers = uprobes / inline
  hooks on the property reader.

**Finding kinds:** `property_read_divergence`,
`property_read_latency_outlier`.

**Harness:** Frida script that hooks `__system_property_get` and
returns spoofed `ro.debuggable=0`. Asserts divergence finding
fires.

---

## Flag 4 — Kernel-level hooks (seccomp / eBPF / kprobes)

**Attacker behaviour:** install a seccomp-bpf filter that
rewrites syscall arguments, or load an eBPF program that
interposes `open`/`read`/`mmap`. Userspace stays clean.

**Detection plan:**

- Read `Seccomp:` from `/proc/self/status` at `JNI_OnLoad`. Any
  post-startup transition into filter mode = installation event
  (legitimate apps typically don't install seccomp filters
  themselves).
- `CapEff:` from `/proc/self/status` for stray
  `CAP_SYS_PTRACE` / `CAP_SYS_ADMIN` on a non-root UID.
- Tight `getpid()` syscall timing loop, baseline vs current.
  Persistent latency outliers = uprobe / kprobe interposition.
  Cheap and root-free; needs careful jitter calibration to avoid
  false positives.

**Finding kinds:** `seccomp_filter_installed_post_boot`,
`syscall_latency_outlier`, `unexpected_capabilities`.

**Harness:** debug build that installs its own seccomp filter
mid-run, or runs under `strace` / `frida-trace` on libc. Asserts
the seccomp transition finding fires.

---

## Flag 5 — Attestation × runtime correlation (captured 1.0.0)

**Status: shipped.** Implementation references:

- Helper: `TelemetryCollector.applyAttestationRuntimeCorrelation()`
  runs after every detector evaluates and before `summary` is
  computed. Composes the existing per-detector findings.
- New IntegritySignal: `HARDWARE_ATTESTED_USERSPACE_TAMPERED`
  (HIGH-tone, "strongest single signal" framing).
- New finding kind: `hardware_attested_but_userspace_tampered`,
  appended to the `attestation.key` detector report's findings
  list (the attestation half is the load-bearing precondition,
  so the derived signal belongs there semantically).
- 11 unit tests covering positive trip, multi-kind aggregation,
  attestation.key targeting (NOT runtime.environment), 4 negative
  cases (no hooks; unverified boot; null attestation; SelfSigned
  verified-boot — only "Verified" counts), idempotency, end-to-end
  IntegritySignal mapping, and graceful behaviour when
  `attestation.key` was filtered out via `CollectOptions.skip`.

**Attacker behaviour caught:** sophisticated attacker on a
TEE-compromised device (or a hardware-attested device running
Magisk + Shamiko hide) where attestation reports clean but ART
is patched. Either signal alone is interesting; the combination
is extraordinary — the hardware says "clean device" and userspace
simultaneously says "active hook injection." Two explanations,
both bad: TEE compromise (rare but exists) or post-attestation
injection (Magisk + Shamiko, etc.).

**Capture criteria** (all met as of 1.0.0):
1. `verifiedBootState == "Verified"` AND any
   `IntegritySignal.HOOKING_FRAMEWORK_DETECTED`-mapped kind in
   the same report → derived finding emitted at CRITICAL severity.
2. The derived finding's `details.tamper_finding_kinds` enumerates
   every distinct hook-related kind that contributed (sorted,
   comma-separated for backend parsing stability).
3. Wire-format additive only — no schema bump, no breaking change.

---

## Flag 6 — Java-side reflection tampering

**Attacker behaviour:** Frida-Java patches via `Method.set*` or
similar reflection without touching `ArtMethod` directly. Rare
but possible.

**Detection plan:** baseline `accessFlags` and method-count hashes
of a small known-stable surface (`java.lang.Object`, `Runtime`,
`System`, `Class`, `String`) at `JNI_OnLoad`. Re-hash on collect.
Mismatch = tampering.

**Finding kinds:** `core_class_method_count_changed`,
`core_class_access_flags_changed`.

**Harness:** Frida-Java script that mutates `Object.hashCode`'s
modifiers via reflection.

---

## Flag 7 — TracerPid race + multi-attach

**Attacker behaviour:** ptrace attach for one syscall and detach.
The current single-shot read at
`RuntimeEnvironmentDetector.kt:196` misses the brief window.

**Detection plan:** background sampler (similar to
`StackWatchdog`) that polls `TracerPid` at ~250 ms intervals
during sensitive windows and OR's the result. Also enumerate
`/proc/self/task/*/comm` for `frida-agent`, `gum-js-loop`,
`gmain` thread names.

**Finding kinds:** `tracer_attached_briefly`,
`suspicious_thread_name_in_process`.

**Harness:** Frida script that calls `Process.detach()` after a
single-syscall hook, demonstrates the race.

---

## Flag 8 — App-cloning frameworks beyond ClonerDetector

**Attacker behaviour:** Island, DualSpace, VirtualXposed —
cloning frameworks that may not trip mount/UID mismatches.

**Detection plan:** read `/proc/self/attr/current` (SELinux
domain) and compare against expected domain for the app UID. Add
`splitNames` consistency check via `PackageManager`.

**Finding kinds:** `selinux_domain_unexpected`,
`split_apk_set_inconsistent`.

**Harness:** install the sample app under VirtualXposed.

---

## Flag 9 — SIGTRAP / signal-handler integrity

**Attacker behaviour:** rewrite signal handlers to swallow
breakpoint traps, hide debugger presence.

**Detection plan:** install a known SIGTRAP handler at
`JNI_OnLoad`. Re-read via `sigaction(..., NULL, &old)` on collect.
Mismatch = handler hijacked.

**Finding kinds:** `signal_handler_hijacked`.

**Harness:** Frida script that calls `sigaction()` to overwrite
SIGTRAP.

---

## Priority order & rough effort

| Flag | Status     | Priority | Effort | Notes                                                                |
| ---- | ---------- | -------- | ------ | -------------------------------------------------------------------- |
| 1    | shipped 0.6.0 | —     | —      | Runtime DEX injection (in-memory + disk + pre-baseline). Captured.   |
| 2    | shipped 0.9.0 | —     | —      | 5 of 8 frameworks (Dobby/Whale/YAHFA/FastHook/il2cpp-dumper). 3 deferred behind embedded-vs-injected. |
| 5    | shipped 1.0.0 | —     | —      | Attestation × runtime correlation. Strongest single signal.          |
| 3    | open       | High     | M      | Shamiko / Magisk-hide property interception. Most-deployed evasion in the wild. |
| 4    | open       | Medium   | L      | Kernel-level hooks (seccomp / eBPF / kprobes). Syscall timing requires jitter calibration. |
| 6    | open       | Low      | M      | Java-side reflection tampering. Marginal additional signal vs Vector A. |
| 7    | open       | Low      | S      | TracerPid race + multi-attach. Cheap; closes a known race-window bypass. |
| 8    | open       | Low      | S      | App-cloning frameworks beyond ClonerDetector. Cloner detector already covers the common case. |
| 9    | open       | Low      | S      | SIGTRAP / signal-handler integrity. Niche; depends on SIGTRAP being a probe vector at all. |

Embedded-vs-injected (the prerequisite for the deferred ShadowHook /
SandHook / Pine signatures from Flag 2) is its own roadmap item —
not currently numbered, but tracked under Flag 2's "deferred"
section above.

This document is updated as flags are captured (a captured flag
moves into the "Coverage today" table and out of the roadmap).
