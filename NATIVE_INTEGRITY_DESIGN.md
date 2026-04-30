# Native Integrity & Anti-Hooking Design

Extends the existing `runtime.environment` detector with layers that protect
the sensor itself from being neutered, and detect injected code that bypasses
signature-based detection.

---

## Threat Model

An attacker who can:
1. Replace or patch `libdicore.so` on disk or in memory
2. PLT/GOT-hook `libdicore.so`'s imported functions (`open`, `read`, `mmap`)
   to feed sanitized data to our detectors
3. Inject an unknown `.so` (Frida gadget, custom agent) that isn't in our
   signature list
4. Interpose at the JNI boundary to intercept calls between Java and native
5. Xposed/LSPosed-hook our Kotlin public API methods to suppress or modify
   reports

...can blind every other detector. These layers close that meta-bypass.

---

## New Finding Kinds

All emitted by `runtime.environment` (detector id: `runtime.environment`).

| Kind | Severity | Trigger |
|------|----------|---------|
| `got_entry_out_of_range` | CRITICAL | `libdicore.so` GOT pointer escapes expected library range |
| `got_entry_drifted` | HIGH | GOT pointer changed since `JNI_OnLoad` snapshot |
| `native_text_hash_mismatch` | CRITICAL | `libdicore.so` `.text` section doesn't match build-time hash |
| `native_text_drifted` | HIGH | `.text` section changed since `JNI_OnLoad` snapshot |
| `injected_library` | HIGH | Loaded `.so` not in build-time manifest and outside system paths |
| `injected_anonymous_executable` | HIGH | Anonymous memory mapping with execute permission outside known regions |
| `native_caller_out_of_range` | HIGH | JNI entry point called from unexpected address (not in `libart` range) |
| `stack_foreign_frame` | HIGH | `@Critical` Kotlin method's stack contains frames from non-allowlisted packages |

---

## Architecture Overview

```
Build time (Gradle plugin)              Runtime (detector scan)
--------------------------              -----------------------

APK lib/<abi>/*.so                      dl_iterate_phdr walk
       |                                        |
       v                                        v
+-- Fingerprint blob --+          +-- Runtime state --+
| - .so filename list  |          | - Loaded libs     |
| - libdicore .text    |          | - GOT values      |
|   SHA-256            |          | - .text hash      |
| - per-file SHA-256s  |          | - Caller addrs    |
+----------------------+          | - Stack traces    |
       |                          +-------------------+
       |                                    |
       +----------> COMPARE <---------------+
                       |
                       v
              Findings emitted in
          runtime.environment report
```

---

## Component 1: Build-Time Additions (Gradle Plugin)

Extends `ComputeFingerprintTask` / `InstrumentApkTask`.

### What gets baked into the fingerprint blob:

1. **`.so` inventory** — list of all filenames in `lib/<abi>/` for the
   target ABI (e.g. `["libdicore.so", "libsqlcipher.so"]`)
2. **`libdicore.so` `.text` hash** — parse the ELF headers of the
   shipped `libdicore.so`, locate the `.text` section by section header,
   compute SHA-256 of its raw bytes
3. **Per-file whole-file SHA-256** — for each `.so` in the inventory
   (used for future expansion; the runtime currently only needs the
   filename set for injected-library detection)

### Implementation notes:

- ELF parsing is straightforward: read the ELF header, walk section
  headers, find `.text` by name (or by `SHF_EXECINSTR` flag), hash
  the bytes at that offset+size
- The fingerprint blob format gains new fields; the runtime
  `FingerprintDecoder` is extended to parse them
- Only the primary ABI's `libdicore.so` is hashed (the one that will
  actually load on the device; `Build.SUPPORTED_ABIS[0]`)

---

## Component 2: GOT Integrity Verification

**File:** `dicore/native_integrity/got_verify.cpp`

### At `JNI_OnLoad`:

1. Use the saved load address of `libdicore.so` (captured during
   `System.loadLibrary` → `JNI_OnLoad`, NOT re-queried via
   `dl_iterate_phdr` which could itself be hooked)
2. Parse our own ELF headers from memory to locate `.got` / `.got.plt`
   sections
3. Walk each resolved GOT pointer and classify it into known library
   ranges discovered via a one-time `dl_iterate_phdr` scan:
   - `libc.so` range
   - `libm.so` range
   - `libdl.so` range
   - `libart.so` range
   - `libdicore.so` range (internal calls)
   - Other known system libraries
4. Store the snapshot (pointer values + classifications) in an
   mmap-protected page (`PROT_NONE` between scans, same pattern as
   `integrity.art`)

### On each scan:

1. Re-read each GOT slot from our own memory
2. Classify the live pointer against the same range map
3. Compare against snapshot:
   - **Drift** (live != snapshot): emit `got_entry_drifted`
   - **Out of range** (live doesn't land in ANY known library):
     emit `got_entry_out_of_range`

### Key details:

- ASLR is handled naturally: ranges are captured at load time, pointers
  are compared against ranges (not absolute addresses)
- `dl_iterate_phdr` is called exactly once at `JNI_OnLoad` (before
  hooks typically land) to build the range map. Later scans reuse the
  saved ranges.
- The GOT snapshot uses the same mmap-protect + hash-verify pattern as
  `integrity.art`'s baseline pages. If an attacker `mprotect`+patches
  the snapshot page itself, the hash check catches it.

---

## Component 3: `.text` Self-Integrity Verification

**File:** `dicore/native_integrity/text_verify.cpp`

### At `JNI_OnLoad`:

1. Using the saved load address + ELF program headers, locate the
   PT_LOAD segment with `PF_X` (executable) — this is the `.text`
   segment
2. Compute SHA-256 of the entire segment → **runtime snapshot hash**
3. Receive the **build-time expected hash** from Kotlin via a one-time
   JNI init call (`NativeBridge.initNativeIntegrity(expectedTextHash)`)
   — Kotlin reads it from the decoded fingerprint blob

### On each scan:

1. Re-hash the `.text` segment (same base address + size, both known
   from load time)
2. Compare against:
   - **Build-time hash** → mismatch = `native_text_hash_mismatch`
     (the `.so` on disk was replaced before loading)
   - **`JNI_OnLoad` snapshot** → mismatch = `native_text_drifted`
     (someone `mprotect`+patched after load)

### Performance:

- `.text` is ~230 KB → SHA-256 takes ~1-2 ms on modern ARM
- Acceptable for a detector that runs every few seconds at most

---

## Component 4: Injected Library Detection

**File:** `dicore/native_integrity/lib_inventory.cpp`

### At `JNI_OnLoad`:

- Receive the build-time `.so` filename list from Kotlin (decoded from
  fingerprint blob)

### On each scan:

1. Walk `dl_iterate_phdr` → collect all loaded shared object paths
2. For each loaded library, apply the allowlist check:

   **Allowed (skip silently):**
   - Path starts with `/system/`
   - Path starts with `/vendor/`
   - Path starts with `/apex/`
   - Path starts with `/data/dalvik-cache/`
   - Filename matches an entry in the build-time manifest

   **Flagged:**
   - Loaded from `/data/app/`, `/data/local/tmp/`, or any other
     non-system path AND not in the build-time manifest
     → emit `injected_library` with the full path in `details`

3. Additionally, scan `/proc/self/maps` for anonymous executable
   mappings:
   - Permission is `r-xp` or `r-xs` (NOT `rwxp` — that's already
     caught by the existing RWX check)
   - No pathname (anonymous)
   - Not `[vdso]`, `[vectors]`, or in the ART JIT cache range

   Each hit → emit `injected_anonymous_executable`

### Rationale:

- Frida's memfd-based gadget injection deliberately avoids leaving a
  filesystem path — it shows up as an anonymous executable mapping
- Unknown injectors that aren't in `MapsParser`'s signature list get
  caught by the manifest comparison
- System libraries are always allowed — they're part of the OS, not
  injected by an attacker

---

## Component 5: JNI Return Address Verification

**File:** `dicore/native_integrity/caller_verify.cpp`

### At `JNI_OnLoad`:

- Capture `libart.so`'s mapped RX range from `dl_iterate_phdr`
- Store as the expected caller range for all JNI entry points

### In each JNI entry point:

A C macro inserted at the top of every `extern "C"` JNI function:

```c
#define DI_VERIFY_CALLER() do { \
    void* ra = __builtin_return_address(0); \
    if (!caller_in_libart_range(ra)) { \
        record_caller_violation(__func__, ra); \
    } \
} while(0)
```

- Compiles to ~4 instructions: load range bounds, compare, branch, append
- If the return address falls outside `libart`'s RX segment, append a
  violation record to a lock-free ring buffer

### Drain:

- `RuntimeEnvironmentDetector` calls `NativeBridge.drainCallerViolations()`
  at scan time
- Each buffered violation becomes a `native_caller_out_of_range` finding
  with `details` containing the function name and the unexpected caller
  address (classified against known ranges for forensics)

### Why `libart` is the expected caller:

- All JNI calls from Java go through ART's JNI dispatch (`art_quick_generic_jni_trampoline` or the compiled stub)
- The return address of a JNI function should always land inside `libart.so`
- If Frida interposes at the JNI level, the call goes through Frida's
  trampoline page → return address lands in attacker-allocated memory

---

## Component 6: Kotlin Stack Verification (`@Critical` + `StackGuard`)

Two complementary mechanisms provide full coverage of the Kotlin layer:
1. **Deterministic verification** at `@Critical` method entry points
2. **Probabilistic watchdog sampling** of the collector thread during
   the entire `collect()` execution window

Together they catch hooks on both public API methods AND internal
detector/helper methods — without instrumenting every method in the
codebase.

---

### Part A: `@Critical` + Deterministic Verification

#### `@Critical` annotation:

```kotlin
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
internal annotation class Critical
```

Marks methods that must verify their call stack before proceeding. The
annotation is documentation + a lint signal; enforcement is via an explicit
`StackGuard.verify()` call at method entry.

#### `StackGuard` object:

```kotlin
internal object StackGuard {
    private val violations = ConcurrentLinkedQueue<StackViolation>()

    fun verify() { /* inspect stack, record violations */ }
    fun drain(): List<StackViolation> { /* return + clear */ }
}
```

**`verify()` logic:**
1. Capture `Throwable().stackTrace`
2. Walk each frame's class name
3. Check the package against the allowlist:
   - `io.ssemaj.deviceintelligence`
   - `kotlin` / `kotlinx`
   - `java` / `javax` / `sun`
   - `android` / `androidx`
   - `com.android`
   - `dalvik`
4. Any frame NOT matching the allowlist → record a `StackViolation`
   containing: the `@Critical` method name, the foreign frame's full
   class name, and a mini stack trace (first 10 frames)

**`drain()` logic:**
- Called by `RuntimeEnvironmentDetector.evaluate()`
- Returns all accumulated violations since last drain
- Each violation becomes a `stack_foreign_frame` finding

#### Applied to these methods:

- `DeviceIntelligence.collect()`
- `DeviceIntelligence.collectJson()`
- `DeviceIntelligence.collectBlocking()`
- `DeviceIntelligence.collectJsonBlocking()`
- `DeviceIntelligence.awaitPrewarm()`
- `DeviceIntelligence.observe()` (at each emission)

#### Example violation:

An LSPosed module hooking `collect()` would produce:

```json
{
  "kind": "stack_foreign_frame",
  "severity": "high",
  "subject": "io.ssemaj.sample",
  "message": "Foreign frame in @Critical method call stack",
  "details": {
    "critical_method": "DeviceIntelligence.collect",
    "foreign_frame": "de.robv.android.xposed.XposedBridge.handleHookedMethod",
    "trace": "...first 10 frames..."
  }
}
```

---

### Part B: Watchdog Thread Stack Sampling

#### Problem:

`@Critical` only covers the 6 public API methods. If LSPosed hooks an
internal method — e.g. `BootloaderIntegrityDetector.evaluate()`,
`KeyAttestationDetector.evaluate()`, `TelemetryCollector.buildAppContext()`,
or any helper — `StackGuard.verify()` won't see it because the hooked
method is deeper in the call chain.

Instrumenting every internal method is impractical (~100+ methods,
massive performance hit). Instead we sample the collector thread
externally.

#### Design:

```kotlin
internal object StackWatchdog {
    private val samples = ConcurrentLinkedQueue<StackViolation>()

    fun watchDuring(targetThread: Thread, block: () -> Unit) {
        val watchdog = thread(name = "di-stack-watchdog", isDaemon = true) {
            while (!Thread.currentThread().isInterrupted) {
                sampleThread(targetThread)
                Thread.sleep(SAMPLE_INTERVAL_MS)
            }
        }
        try {
            block()
        } finally {
            watchdog.interrupt()
        }
    }

    fun drain(): List<StackViolation> { /* return + clear */ }
}
```

#### How it works:

1. `TelemetryCollector.collect()` wraps its detector-execution loop
   inside `StackWatchdog.watchDuring(Thread.currentThread()) { ... }`
2. The watchdog thread wakes every **100ms** and calls
   `targetThread.stackTrace` (the collector thread)
3. Each sample is analyzed with the same allowlist logic as
   `StackGuard.verify()` — any foreign frame is recorded
4. A typical `collect()` runs for ~5-6 seconds → **50-60 samples**
   across the full execution window
5. Any persistent hook (LSPosed hooks are active for the entire
   process lifetime) will appear in multiple samples

#### Why this catches internal hooks:

When the watchdog samples the collector thread mid-execution of a
hooked `BootloaderIntegrityDetector.evaluate()`, the captured stack
looks like:

```
io.ssemaj.deviceintelligence.internal.BootloaderIntegrityDetector.evaluate
de.robv.android.xposed.XposedBridge.handleHookedMethod   <-- FOREIGN
io.ssemaj.deviceintelligence.internal.TelemetryCollector.collect
io.ssemaj.deviceintelligence.DeviceIntelligence.collect
...
```

The foreign frame is detected and recorded.

#### Sampling parameters:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Sample interval | 100 ms | Each detector runs ~50-500ms; 100ms guarantees at least 1 sample per detector |
| Max samples per collect | 100 | Cap to prevent unbounded memory on very slow devices |
| Dedup window | Per unique foreign frame class | Don't record the same hook 50 times; once per unique class is enough |

#### Performance:

- `Thread.getStackTrace()` on another thread: ~0.5 ms per call
- 50-60 samples × 0.5 ms = ~25-30 ms total on the watchdog thread
- **Zero overhead on the collector thread** — `getStackTrace()` is
  called from the watchdog; the collector thread only pays for
  safepoint overhead (a few microseconds per sample, same as GC
  safepoints)
- The watchdog thread is daemon + interrupted on completion → no leak

#### Finding kind:

Same `stack_foreign_frame` finding kind as Part A, with an additional
`details` field:

```json
{
  "kind": "stack_foreign_frame",
  "severity": "high",
  "subject": "io.ssemaj.sample",
  "message": "Foreign frame detected in collector thread stack sample",
  "details": {
    "source": "watchdog_sample",
    "sample_index": "7",
    "foreign_frame": "de.robv.android.xposed.XposedBridge.handleHookedMethod",
    "hooked_method": "io.ssemaj.deviceintelligence.internal.BootloaderIntegrityDetector.evaluate",
    "trace": "...first 10 frames..."
  }
}
```

#### Edge cases:

- **Short-lived hooks** (hook, execute, unhook within <100ms): caught
  probabilistically. With 100ms interval, a hook that lives for 200ms
  has ~86% chance of being sampled. Hooks that live for the full
  detector duration (~500ms+) are virtually guaranteed to be caught.
- **Hook on `Thread.getStackTrace()` itself**: this is a `java.lang`
  method — hooking it trips `integrity.art` Vector A/F.
- **Hook on `StackWatchdog` itself**: the watchdog class is in
  `io.ssemaj.deviceintelligence.internal` — hooking it trips the
  deterministic `StackGuard.verify()` check at the `collect()` entry
  point (the foreign frame appears in the entry-point stack).

---

### Combined coverage matrix:

| Hook target | Part A (deterministic) | Part B (watchdog) |
|-------------|----------------------|-------------------|
| `DeviceIntelligence.collect()` | YES | YES |
| `TelemetryCollector.collect()` | NO | YES |
| Any `Detector.evaluate()` | NO | YES |
| Internal helpers (`buildDeviceContext`, etc.) | NO | YES |
| `NativeBridge.*` (Kotlin side) | NO | YES |
| `StackGuard.verify()` itself | Via integrity.art | YES (watchdog is independent) |
| `StackWatchdog` itself | YES (entry-point check) | Via integrity.art |

---

## Performance Budget

| Check | Cost per scan | Thread | Notes |
|-------|--------------|--------|-------|
| GOT verify | <1 us | Collector | ~20 pointer comparisons |
| `.text` re-hash | ~1-2 ms | Collector | SHA-256 of ~230 KB |
| Library inventory | <0.5 ms | Collector | `dl_iterate_phdr` walk (~50 entries) |
| JNI caller check | 0 (already happened) | Collector | Drain is O(violations), typically 0 |
| Kotlin StackGuard (Part A) | ~3 ms | Collector | `Throwable().stackTrace` at 6 call sites |
| Stack Watchdog (Part B) | ~25-30 ms | Background | 50-60 samples on daemon thread, zero collector overhead |
| **Total on collector thread** | **~5 ms** | | vs existing 5-6s `runtime.environment` scan |
| **Total on background thread** | **~25-30 ms** | | Parallel, no user-visible latency impact |

---

## Integration Points

### Fingerprint blob (`Fingerprint` data class):

New fields:
```
soInventory: List<String>          // filenames in lib/<abi>/
dicoreTextSha256: String           // hex SHA-256 of .text section
soHashes: Map<String, String>      // filename -> whole-file SHA-256 (future use)
```

### `NativeBridge` new JNI methods:

```kotlin
external fun initNativeIntegrity(
    expectedTextHash: String,
    expectedSoList: Array<String>,
): Boolean

external fun scanGotIntegrity(): Array<String>?
external fun scanTextIntegrity(): Array<String>?
external fun scanLoadedLibraries(): Array<String>?
external fun drainCallerViolations(): Array<String>?
```

### `TelemetryCollector.collect()` integration:

The detector-execution loop is wrapped in `StackWatchdog.watchDuring()`:
```kotlin
StackWatchdog.watchDuring(Thread.currentThread()) {
    for (det in activeDetectors) { ... }
}
```

### `RuntimeEnvironmentDetector.doEvaluate()` additions:

After the existing maps/debugger/hook/RWX checks:
1. Call `NativeBridge.scanGotIntegrity()` → parse, emit findings
2. Call `NativeBridge.scanTextIntegrity()` → parse, emit findings
3. Call `NativeBridge.scanLoadedLibraries()` → parse, emit findings
4. Call `NativeBridge.drainCallerViolations()` → parse, emit findings
5. Call `StackGuard.drain()` → emit findings (Part A: deterministic)
6. Call `StackWatchdog.drain()` → emit findings (Part B: sampled)

### Caching:

- GOT integrity: **cached for process lifetime** (GOT doesn't
  legitimately change after lazy binding completes)
- `.text` integrity: **re-scanned every call** (like `integrity.art` —
  a post-attach patching can happen at any time)
- Library inventory: **re-scanned every call** (injection can happen
  at any time)
- Caller violations: **accumulated, drained per scan** (ring buffer)
- Stack violations (Part A): **accumulated, drained per scan** (queue)
- Stack samples (Part B): **accumulated during collect(), drained per scan** (queue, deduped by foreign frame class)

---

## Bypass Model (honest assessment)

| Layer | How an attacker bypasses it | Cost to attacker |
|-------|-----------------------------|-----------------|
| GOT verify | Inline-hook the function body instead of GOT-patching (needs `.text` patching, which trips self-integrity) | High — must chain with .text bypass |
| `.text` self-integrity | Patch the hash comparison itself, or patch the snapshot page AND the SHA-256 function | Very high — circular dependency (patching the verifier trips the verifier) |
| Injected library detection | Use `memfd_create` + anonymous mapping (trips anonymous-exec check), or hook `dl_iterate_phdr` (trips GOT check) | High — all escape routes are covered by another layer |
| JNI caller verify | Call JNI functions indirectly through a libart trampoline (complex, version-specific) | Medium-high |
| Kotlin StackGuard (Part A) | Hook `Throwable.getStackTrace()` to filter frames (trips `integrity.art` Vector A/E/F) | High — requires ART-level hook which is already detected |
| Stack Watchdog (Part B) | Hook `Thread.getStackTrace()` to filter frames (same ART-level hook, trips Vector A/E/F). OR kill the watchdog thread (the collector detects this via `Thread.isAlive` check after completion and emits a finding). OR reduce hook duration to <100ms per call (impractical for persistent Xposed hooks which wrap the entire method execution) | Very high — no clean escape route |

The layers form a **circular dependency**: bypassing one requires
patching code that is monitored by another. No single bypass neuters
the system.

---

## File Layout (new files)

```
deviceintelligence/src/main/cpp/dicore/native_integrity/
    got_verify.cpp          // GOT snapshot + scan
    got_verify.h
    text_verify.cpp         // .text hash + scan
    text_verify.h
    lib_inventory.cpp       // dl_iterate_phdr inventory scan
    lib_inventory.h
    caller_verify.cpp       // JNI return-address ring buffer
    caller_verify.h
    caller_verify_macro.h   // DI_VERIFY_CALLER() macro

deviceintelligence/src/main/kotlin/.../internal/
    StackGuard.kt           // @Critical annotation + deterministic violation accumulator
    StackWatchdog.kt        // Background thread stack sampler during collect()
    NativeIntegrityFindings.kt  // Finding builders for the 8 new kinds

deviceintelligence-gradle/src/main/kotlin/.../gradle/internal/
    ElfParser.kt            // Minimal ELF section-header parser for .text extraction
```

---

## Success Criteria

1. On a clean device: zero new findings (all checks pass silently)
2. Frida `Interceptor.attach` on any `libdicore.so` JNI export:
   triggers `native_caller_out_of_range`
3. Frida `Interceptor.replace` on `open`/`read` via GOT:
   triggers `got_entry_drifted` + `got_entry_out_of_range`
4. `libdicore.so` replaced with a neutered build:
   triggers `native_text_hash_mismatch`
5. `mprotect` + byte-patch on `.text` after load:
   triggers `native_text_drifted`
6. Frida gadget injected via `frida -U -f`:
   triggers `injected_library` or `injected_anonymous_executable`
7. LSPosed hooking `DeviceIntelligence.collect()`:
   triggers `stack_foreign_frame` (via Part A deterministic check)
8. LSPosed hooking any internal detector (e.g.
   `BootloaderIntegrityDetector.evaluate()`):
   triggers `stack_foreign_frame` (via Part B watchdog sampling)
9. LSPosed hooking any internal helper (e.g.
   `TelemetryCollector.buildDeviceContext()`):
   triggers `stack_foreign_frame` (via Part B watchdog sampling)
10. All of the above show up in the `runtime.environment` detector
    section of the JSON report with correct severity and details
11. Watchdog thread adds zero latency to the collector thread's
    critical path (background-only cost)
12. Watchdog thread is properly cleaned up (interrupted + joined)
    after each `collect()` pass — no thread leaks
