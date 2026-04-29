# integrity.art red-team harness

Frida scripts that intentionally trigger the corresponding
`integrity.art` finding so a developer can validate that the
detector still fires after a code change. There is one script
per attack vector plus one end-to-end script that exercises the
real-world Frida-Java hook API.

The script labels still print under the historical `F18-vector-*`
prefix because that is the attack-vector taxonomy this harness
was built around (Vectors A/C/D/E/F). The detector itself ships
on the wire as `integrity.art`.

These are **offensive** scripts. Run them only on a device you
own, on a debug build of the sample app. They have no use in
production and must never ship in a release APK.

## Pre-reqs

- A **rooted** Android device (KernelSU on Pixel 6 Pro is the
  reference setup), or an AOSP `userdebug` build with `adb root`
  available. Frida-server on stock Android `user` builds runs as
  the `shell` user (uid 2000), which lacks `CAP_SYS_PTRACE` and
  therefore cannot inject into another app's process — the
  scripts will fail to attach. SELinux must be permissive
  (`su -c 'setenforce 0'` on KernelSU) for `ptrace` to succeed.
- `frida-tools` on the host whose major version matches
  `frida-server` on the device (Frida is strict about this).
  Quick host install:
  ```bash
  python3 -m venv ~/.frida-venv
  ~/.frida-venv/bin/pip install 'frida-tools'
  ~/.frida-venv/bin/frida --version
  ```
- `frida-server` running on the device, version-matched to the
  host CLI. Quick rooted-device setup:
  ```bash
  adb push frida-server-XX.Y.Z-android-arm64 /data/local/tmp/frida-server
  adb shell "su -c 'chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
  ```
- The DeviceIntelligence sample app installed and **already
  running**. Frida attaches to a live process; `integrity.art`'s
  snapshot is captured at `JNI_OnLoad` *before* the script
  attaches, so the drift checks have a clean baseline to compare
  against.

## Coverage matrix

`integrity.art` ships five attack-vector detectors. The table below lists
every script in this folder, the vector it primarily exercises,
and the finding kinds it triggers on the reference Pixel 6 Pro
(API 36) under KernelSU.

| Script                      | Primary vector       | Findings emitted                                                                                                                                                                            |
| --------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `frida-vector-a.js`         | Vector A             | `art_method_entry_drifted` (HIGH) + `art_method_entry_out_of_range` (HIGH) on `Object#<init>`. Patches `entry_point_from_quick_compiled_code_` to a Frida-allocated trampoline.              |
| `frida-vector-c.js`         | Vector C             | `jni_env_table_drifted` (HIGH) + `jni_env_table_out_of_range` (HIGH) on `GetMethodID`. Swaps `JNIEnv->functions->GetMethodID` to a Frida `Memory.alloc` page.                                |
| `frida-vector-d.js`         | Vector D             | `art_internal_prologue_drifted` (HIGH) + `art_internal_prologue_baseline_mismatch` (MEDIUM) on `art::ArtMethod::Invoke`. Inline trampoline patches the prologue.                              |
| `frida-vector-e.js`         | Vector E             | `art_method_jni_entry_drifted` (HIGH) on `Object#hashCode`. Overwrites `entry_point_from_jni_` (the `data_` slot) directly.                                                                  |
| `frida-vector-f.js`         | Vector F             | `art_method_acc_native_flipped_on` (HIGH) on `String#length`. Flips `ACC_NATIVE` (0x100) ON in `access_flags_`.                                                                              |
| `frida-vector-frida-java.js`| Real Frida-Java hook | The cls.method.implementation = ... API. See **What Frida-Java actually changes** below. The cleanest signal is two `art_method_entry_drifted` (HIGH) findings emitted just from Frida-Java attaching. |

## Usage

Each script:

1. **Pre-warms** Frida's Java bridge by caching every `Java.use`
   binding it will need post-tamper. This is critical: once
   `Object.hashCode` or `JNIEnv->GetMethodID` is hooked,
   Frida-Java's own internal lookups can recurse infinitely or
   crash the bridge.
2. **Dry-runs** an `integrity.art` collect to capture a baseline
   (and to prove that the same scan is clean before tampering).
3. **Tampers** with the target field.
4. **Verifies** the post-tamper `integrity.art` findings, either
   by calling a fresh `DeviceIntelligence.collect()` (Vectors C,
   D, F) or by inspecting the in-window scan records directly
   (Vectors A, E, frida-java) when the tamper would crash the
   verify path.
5. **Restores** the original value before exiting.

```bash
# Get the live PID of the sample app on a rooted device:
PID=$(frida-ps -D <device-id> -ai | awk '/io\.ssemaj\.sample/ {print $1}')

# Run any vector script against it:
frida -D <device-id> -p $PID -q \
  -l tools/red-team/_verify_helper.js \
  -l tools/red-team/frida-vector-a.js
```

> **Important: pass `_verify_helper.js` first.** Every vector
> script depends on the `artPrepare` / `artVerifyAndReport`
> helpers it defines (formerly `f18Prepare` /
> `f18VerifyAndReport`; the old names remain as backwards-
> compat shims).

### Two-device smoke harness

`_m17_smoke.sh` runs the full sweep end-to-end: clean baseline
plus all 6 vector scripts on the rooted reference device, plus
a Frida-free clean-baseline read on the unrooted secondary
device (logcat parses the on-device `DeviceIntelligence.collect()`
JSON to confirm zero `integrity.art` findings). Edit the device
IDs at the top of the script to point at your own hardware:

```bash
bash tools/red-team/_m17_smoke.sh
ls build/m17/   # per-(device,script) logs
```

`_clean_baseline.js` is a no-op script that just runs
`artVerifyAndReport`; useful for confirming Frida-attach
behaviour on a given device without running any tamper.

## What Frida-Java actually changes

`frida-vector-frida-java.js` exists as the canonical end-to-end
test for the most commonly-asked question: "does `integrity.art`
catch a real `cls.method.implementation = ...` hook?". The
answer in practice on Android 13-16 is more nuanced than a
single yes/no, and the script is documented inline so a future
maintainer can reproduce the analysis.

Empirical findings on Pixel 6 Pro (API 36) with frida-tools 17.x:

- **Frida-Java attach itself** — i.e. the `Java.use(...)` and
  `Java.cast(...)` machinery initialising — causes
  `Object#hashCode` and `Object#getClass` to drift from
  `jit_cache → libart`. Vector A's drift filter (M14b) reports
  both as `art_method_entry_drifted`. **This means
  `integrity.art` detects Frida's mere presence in the process
  even before the user installs any application-level hook.**
- `cls.method.implementation = ...` on a JIT-resident
  non-native method (`String#length` is the worked example)
  redirects `entry_point_from_quick_compiled_code_` to another
  jit_cache address. This `jit_cache → jit_cache` transition
  is **suppressed by the drift filter** because ART legitimately
  re-JIT-compiles methods within the same cache region; we
  can't distinguish Frida-Java's bridge from benign
  recompilation at this layer.
- The same hook does **not** modify `entry_point_from_jni_`
  (Vector E's field) or the `ACC_NATIVE` bit (Vector F's
  field). Those vectors stay quiet for `cls.method.implementation`
  on non-native targets.
- For declared-`native` JDK methods (Object#hashCode,
  Object#getClass etc) Frida-Java's hook moves the Vector-A
  entry from jit_cache to libart, which the drift filter
  **does** report (since this is the canonical Frida-attach
  signature anyway, both detect the same event from different
  angles).

## Negative-control check

Every script runs a **dry-run verify before tampering** (visible
in its output as
`[<label> dry-run] integrity.art status=OK ... findings=N`).
On a clean process before Frida is attached the dry-run reports
zero `integrity.art` findings — verified on a fresh launch of
the sample app on Pixel 6 Pro and Pixel 9 Pro.

After Frida attaches the dry-run typically shows two
`art_method_entry_drifted` findings (the
`Object#hashCode/getClass` jit_cache → libart transition above).
Those are real signal: Frida is in the process. They should
not be confused with the per-vector findings the actual tamper
produces.

## Why `frida-vector-a.js` patches the field directly

`integrity.art` Vector A monitors
`ArtMethod->entry_point_from_quick_compiled_code_`, the slot
every Xposed-family hooker (Xposed, EdXposed, LSPosed, YAHFA,
Pine, SandHook, Whale) rewrites. Frida-Java's
`cls.method.implementation = ...` looks like the same kind of
hook from outside but patches different internals (see above).

The Vector A red-team script therefore uses raw JNI calls
(`FindClass` + `GetMethodID`) to obtain the `ArtMethod*` and
overwrites `entry_point_from_quick_compiled_code_` directly —
exactly the canonical Xposed-family attack `integrity.art` was
built to catch. **A real LSPosed module hooking the same method
would trigger the same finding** (the bit-pattern of the write
is identical), so this script doubles as the LSPosed-equivalent
verification path without needing a real LSPosed module
installed.

To keep the tamper window safe (patching `Object.<init>` will
crash any Java allocation that happens through it), the script
saves the original entry, runs ONE direct native scan call,
restores the entry, and only then processes the captured
records.

## Cleanup

`Ctrl-C` the Frida CLI to detach. The hook is removed, but
`integrity.art` will continue to report any drift it captured
during the tamper window for the rest of the process lifetime
(its snapshot is permanent; restoring the live state to match
the snapshot would require a process restart).

## Why the harness is not run in CI

The CTF design intentionally keeps validation manual. CI in
this repo runs only host-side JVM unit tests
(`ArtIntegrityDetectorTest`, `ArtIntegrityTelemetryJsonTest`)
which synthesise the native record format and exercise the
finding-emission logic. Live Frida injection requires:

- a rooted physical device (CI labs rarely have these),
- a per-Android-version frida-server binary,
- a per-CLI-version frida-tools host install,
- SELinux permissive mode for ptrace.

The trade-off: the SDK ships with deterministic JVM tests for
parsing/emission, plus this harness for periodic manual
red-team verification on real hardware.
