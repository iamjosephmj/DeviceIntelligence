---
title: Flag 1 — Pixel 6 Pro on-device runbook
status: living document
---

# Flag 1 on-device runbook (Pixel 6 Pro)

Step-by-step procedure for capturing CTF Flag 1 — runtime DEX
injection — on a rooted Pixel 6 Pro with both Zygisk and
LSPosed installed. Three independent harnesses, three scenarios.

Reference setup:
- Device: Pixel 6 Pro on Android 14/15/16 stock or AOSP, rooted
  via Magisk (Zygisk enabled) **and** LSPosed installed via the
  Zygisk-LSPosed module.
- Host: Linux/macOS with `adb`, optionally `frida-tools` for
  scenario 0.
- Build prerequisites:
  ```bash
  ./tools/red-team/flag1-payload/build-payload.sh
  ./gradlew :samples:minimal:assembleDebug \
            :samples:lsposed-tester:assembleDebug
  ```

## Install once

```bash
# Sample app under test (the target io.ssemaj.sample)
adb install -r samples/minimal/build/outputs/apk/debug/minimal-debug.apk

# LSPosed-tester APK — declares all three Flag 1 entry points
adb install -r samples/lsposed-tester/build/outputs/apk/debug/lsposed-tester-debug.apk

# Optional — push the disk-backed DEX so channel-a paths can fire
adb push tools/red-team/flag1-payload/payload.dex \
         /data/local/tmp/flag1-payload.dex
adb shell chmod 0644 /data/local/tmp/flag1-payload.dex
```

In the LSPosed Manager UI:
1. Modules → enable **DI LSPosed Tester**.
2. Scope picker → tick **io.ssemaj.sample**.
3. **Important:** for clean signal, enable only **one** of the
   three xposed_init entries at a time by editing the module's
   `assets/xposed_init` and rebuilding. Or run all three; just
   read the per-tag log lines independently. The runbook below
   assumes one at a time.

## Scenario 0 — Frida (sanity baseline; should already work)

Validates the detector against the same code path the original
Frida CTF harness exercises. If this captures, the detector is
working at all; if it doesn't, stop here and debug the install
before moving on.

```bash
PID=$(frida-ps -D <device> -ai | awk '/io\.ssemaj\.sample/ {print $1}')
frida -D <device> -p $PID -q -l tools/red-team/dex-injection-inmemory.js
```

Expected:
```
[flag1-inmemory baseline] runtime.environment status=OK dex-injection-findings=0 (of N total)
[flag1-inmemory] DEX payload size = 772 bytes
[flag1-inmemory] InMemoryDexClassLoader installed: ...
[flag1-inmemory post-tamper] runtime.environment status=OK dex-injection-findings=M (of N total)
  #1 kind=dex_in_memory_loader_injected severity=HIGH ...
  #2 kind=dex_in_anonymous_mapping severity=HIGH ...
[flag1-inmemory] FLAG CAPTURED — clean baseline + injection-attributable finding(s)
```

> The Frida script filters the `runtime.environment` finding
> stream to just the five `DexInjection`-emitted kinds
> (`dex_classloader_added`, `dex_path_outside_apk`,
> `dex_in_memory_loader_injected`, `dex_in_anonymous_mapping`,
> `unattributable_dex_at_baseline`) so unrelated
> `runtime.environment` findings (`hook_framework_present`,
> `rwx_memory_mapping`, native G2-G7 layers, …) don't muddle
> the FLAG verdict.

## Scenario 1 — LSPosed late hook (`DexInjectionHook`)

Validates that **non-Frida same-window** DEX injection also
trips the detector. The hook injects via `InMemoryDexClassLoader`
and (optionally) `DexClassLoader` ~2.5 s after app launch — well
after the prewarm has captured the baseline.

Force-stop and restart the sample app, then watch the LSPosed
log:
```bash
adb shell am force-stop io.ssemaj.sample
adb shell am start -n io.ssemaj.sample/.MainActivity   # adjust to your launcher activity
adb logcat -s DI-LSPDexHook
```

Expected:
```
DI-LSPDexHook: scheduled DEX-injection harness for io.ssemaj.sample
DI-LSPDexHook: step 1: baseline collect (locks DexInjection helper snapshot)
DI-LSPDexHook: [DI-LSPDexHook baseline] runtime.environment dex-injection findings=0
DI-LSPDexHook: step 2a: InMemoryDexClassLoader injection (channel b)
DI-LSPDexHook: in-memory loader=... resolved=Payload
DI-LSPDexHook: step 3: post-tamper collect
DI-LSPDexHook: [DI-LSPDexHook post-tamper]   finding kind=dex_in_anonymous_mapping ...
DI-LSPDexHook: [DI-LSPDexHook post-tamper] runtime.environment dex-injection findings=N
DI-LSPDexHook: FLAG CAPTURED — post-tamper delta: [...]
```

If the disk payload was pushed, you should also see
`kind=dex_path_outside_apk` in the post-tamper findings.

## Scenario 2 — LSPosed pre-baseline hook (`EarlyDexInjectionHook`)

**This is the diagnostic test for the Zygisk timing gap.** It
injects synchronously in `handleLoadPackage`, before the
prewarm has a chance to capture the baseline. The injection
becomes part of the baseline snapshot.

Same restart + logcat pattern, different tag:
```bash
adb shell am force-stop io.ssemaj.sample
adb shell am start -n io.ssemaj.sample/.MainActivity
adb logcat -s DI-LSPEarlyHook
```

**Expected outcomes (in order of likelihood):**

A. **`FLAG NOT CAPTURED — pre-baseline timing gap confirmed`** —
   The hypothesis was right. Channel (a) saw the foreign DEX as
   part of the snapshot; channel (b) snapshotted the maps after
   ART had already minted the anon region. The detector needs an
   `unattributable_dex_at_baseline` signal. → **Next step:**
   implement that signal; re-run scenario 2; should now capture.

B. **`FLAG CAPTURED — pre-baseline injection still surfaced`** —
   Channel (b) won the race. ART deferred minting the anon
   region until the first class load (which we trigger
   *after* the prewarm), so the maps snapshot was clean and
   only the post-injection collect saw the new region. → Lucky
   timing; the gap is smaller than feared. Still worth fixing
   for robustness, but lower priority.

C. **No log output / hook didn't run** — `xposed_init` mis-set
   or LSPosed scope not applied. Re-check module settings.

## Scenario 3 — Real Zygisk module (TBD)

Production-realistic test. If scenario 2 reveals the gap and we
fix the detector, scenario 3 verifies the fix actually works
against real Zygisk. The Zygisk module is not yet built —
flagged under CTF roadmap Flag 1 follow-up. Build it after
scenarios 1+2 are validated and the detector is updated.

## Reading the per-detector report off-device

To inspect the actual JSON the detector produced (for forensic
analysis or when the brief log lines aren't enough), the sample
app's debug build dumps each `collectJson()` to logcat under tag
`DI-Sample`. The DEX-injection findings live inside the
`runtime.environment` detector block (no separate `runtime.dex`
ID — the helper feeds findings through the existing process-wide
hook detector):
```bash
adb logcat -s DI-Sample | grep -A 100 '"id": "runtime.environment"'
```

For the cumulative session view (the new shape introduced in
0.7.0), `SessionFindings.toJson()` produces a parallel wire
format with per-finding `first_seen_at_epoch_ms` /
`last_seen_at_epoch_ms` / `observation_count` / `still_active`
fields. The sample app doesn't dump that directly to logcat
today; if you want to inspect it, add a `Log.i(TAG,
session.toJson())` line in `MainActivity.applyReport()`.

## What to report back

After scenarios 1 + 2:
- For each: pasted last 30 lines of `adb logcat -s <TAG>`.
- Whether `FLAG CAPTURED` or `FLAG NOT CAPTURED` appeared.
- The DEX-injection finding kinds list from the post-tamper
  `runtime.environment` slice.

That tells us whether to (a) ship as-is, (b) tune the
detection further (e.g. consolidate the noisy
`unattributable_dex_at_baseline` emit shape), or (c) build
and run the actual Zygisk module to confirm the production-
realistic behaviour matches scenario 2.
