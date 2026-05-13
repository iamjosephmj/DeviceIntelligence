# DeviceIntelligence detectors

Per-detector reference. Read [`README.md`](../README.md) first for
the project-level overview, the wire-format philosophy, and how to
wire the SDK into your app. This document is the deep dive: what
each detector observes, the threat model it's built around, the
finding shapes a backend will receive, the costs, and the known
caveats.

## How to read this document

Three conventions worth pinning before the per-detector sections:

- **Severity ladder.** `low` / `medium` / `high` / `critical`. The
  library *suggests* a severity per finding; backends are free to
  override per their own policy. The ladder is consistent across
  detectors so a backend can build one severity-aware view of the
  whole report.
- **Finding shape.** Every detector emits zero or more `Finding`
  entries inside its `DetectorReport`. Stable fields a backend can
  key on across releases that share the same `schema_version`:
  `kind`, `severity`, `subject`, `message`. The `details` map is
  diagnostic data only — its keys may change between releases
  without a `schema_version` bump.
- **`status` vs `findings` semantics.** `status` answers *"did the
  detector run?"* (`ok` / `inconclusive` / `error`). `findings`
  answers *"what did it see?"*. A clean detector that ran fine
  reports `status: "ok"` with `findings: []`. A detector that ran
  fine and caught something reports `status: "ok"` with one or
  more entries in `findings`. Drive the "did anything trip?"
  decision off `summary.detectors_with_findings`, not off `status`.
  See the same-named section in [`README.md`](../README.md#status-vs-findings--read-this-once)
  for the full rationale.

## Detectors at a glance

| ID                        | One-line purpose                                                                                  | Severity ceiling | Permissions |
| ------------------------- | ------------------------------------------------------------------------------------------------- | ---------------- | ----------- |
| `integrity.apk`           | APK bytes vs. the build-time fingerprint baked by the Gradle plugin                                | critical         | none        |
| `integrity.bootloader`    | Cross-checks `attestation.key`'s chain to surface TEE spoofing / cached chains                     | high             | none        |
| `integrity.art`           | In-process ART tampering across five orthogonal vectors (Vectors A / C / D / E / F)                | high             | none        |
| `attestation.key`         | TEE / StrongBox attestation: Verified Boot, bootloader lock, OS patch level + always-shipped chain | critical         | none        |
| `runtime.environment`     | Debugger / hooker libs / RWX trampolines / `ro.debuggable` mismatch                                | high             | none        |
| `runtime.root`            | `su` binary, Magisk artifacts, `test-keys`, root-manager apps                                      | high             | `QUERY_ALL_PACKAGES` (opt-out via manifest-merger; only the `root_manager_app_installed` channel is affected) |
| `runtime.emulator`        | CPU-instruction-level signals (arm64 MRS / x86\_64 CPUID hypervisor bit)                           | high             | none        |
| `runtime.cloner`          | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches                              | high             | none        |

## Categories

The detector ID is a `<category>.<scope>` pair. Three categories,
each answering a different question:

- **`integrity.*`** — *"does this thing match what we expect?"*
  These detectors compare the live state of an asset (the running
  APK, the bootloader / verified-boot chain, the ART
  data structures) against a known-good reference and emit findings
  on divergence. Reference can be a build-time baked fingerprint
  (`integrity.apk`), a TEE-attested cross-check (`integrity.bootloader`),
  or a JNI_OnLoad snapshot of in-process state (`integrity.art`).
- **`attestation.*`** — *"what does the hardware root-of-trust
  say?"* The only category that produces TEE-signed evidence on
  every report. `attestation.key` is the only entry today; its raw
  cert chain (`app.attestation.chain_b64`) is the single
  authoritative signal in the whole report once a backend
  re-verifies it against Google's pinned attestation root +
  revocation list.
- **`runtime.*`** — *"is the live process / device anomalous in a
  way that suggests instrumentation, root, an emulator, or a
  parallel-app framework?"* These detectors observe the live
  environment for known signals; they don't compare against a
  reference. Useful for fleet-wide cohorting — a single
  `runtime.*` finding is rarely authoritative on its own, but the
  base rate across your install base often is.

---

## `integrity.apk`

Compares the live, on-disk APK against the build-time
`Fingerprint` that the DeviceIntelligence Gradle plugin baked into
it. Any structural divergence becomes a `Finding`; a clean run
produces an empty findings list with `status: "ok"`.

The fingerprint blob lives at
`assets/io.ssemaj.deviceintelligence/fingerprint.bin`, XOR-encrypted
with a per-build key whose chunks are split across generated
Kotlin classes (cost amplifier — defeats `unzip + grep` and naive
blob substitution; not real encryption). The detector decrypts
the blob, then asks `libdicore.so` to walk the on-disk APK ZIP
entries and SHA-256 each one for comparison.

### Threat model

`integrity.apk` is the layer that catches an attacker who took
your release APK, modified one or more entries (Smali edit, native
lib swap, asset replacement), re-signed it with their own key, and
re-distributed it. The detector trips on:

- The runtime signer cert SHA-256 not matching the one baked at
  build time (`apk_signer_mismatch`, CRITICAL) — the strongest
  signal, since a re-signed APK can't reproduce the original
  signer.
- The runtime `applicationInfo.sourceDir` not pointing at a
  `*.apk` file under `/data/app` (`apk_source_dir_unexpected`,
  HIGH) — catches sideloading hosts that re-mount the APK from
  a non-standard path.
- An entry present at build time but missing / modified / added at
  runtime (`apk_entry_removed`, `apk_entry_modified`,
  `apk_entry_added`, all HIGH) — catches partial re-packaging
  attacks where the attacker kept the signing key but mutated
  the contents.
- The fingerprint blob itself missing / corrupt / encrypted with
  the wrong key (`fingerprint_asset_missing` /
  `fingerprint_key_missing` / `fingerprint_bad_magic` /
  `fingerprint_corrupt`, all CRITICAL) — these look like
  attack: the asset was either stripped or replaced.

The detector also emits an `installer_not_whitelisted` (HIGH)
when the APK was installed by a package not on the consumer's
allow-list (configured via the Gradle plugin DSL).

### Finding kinds

| Finding kind                  | Severity | Triggered when                                                                                              |
| ----------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `apk_signer_mismatch`         | critical | The runtime APK's signer cert SHA-256 does not match any signer baked into the fingerprint blob              |
| `apk_source_dir_unexpected`   | high     | `applicationInfo.sourceDir` does not point at a `*.apk` file (sideload-rehost host)                          |
| `apk_entry_removed`           | high     | An entry the fingerprint expected is missing from the live APK ZIP                                           |
| `apk_entry_modified`          | high     | An entry's SHA-256 differs between baked fingerprint and live APK                                            |
| `apk_entry_added`             | high     | The live APK ZIP carries an entry the fingerprint did not bake                                              |
| `installer_not_whitelisted`   | high     | The package's installer (per `PackageManager.getInstallSourceInfo`) is not on the consumer's allow-list      |
| `fingerprint_asset_missing`   | critical | The build-time fingerprint asset is absent at runtime (someone stripped it)                                  |
| `fingerprint_key_missing`     | critical | The generated key class isn't on the runtime classpath (someone Smali-edited the codegen out)                |
| `fingerprint_bad_magic`       | critical | The blob exists and decrypted, but its magic header doesn't match (replaced with a forged blob)              |
| `fingerprint_corrupt`         | critical | The blob is structurally invalid after decryption (mid-build truncation, partial overwrite)                  |

### Sample tripped JSON

```json
{
  "id": "integrity.apk",
  "status": "ok",
  "duration_ms": 132,
  "findings": [
    {
      "kind": "apk_signer_mismatch",
      "severity": "critical",
      "subject": "io.ssemaj.sample",
      "message": "Runtime signer cert does not match the fingerprint baked at build time",
      "details": {
        "expected_sha256": "a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4",
        "runtime_sha256": "98ab45b7278ad8011783b8cdd5e3a62a06ce2d7498755150fae61bc146782a0b"
      }
    }
  ]
}
```

This is the canonical "someone re-signed our APK" signal — the
two SHA-256s are deterministic across runs, so a backend can
correlate the runtime signer hash across the fleet to spot a
specific re-signed build being distributed to many devices.

### Costs

Decrypts a small blob, walks the APK ZIP central directory, and
SHA-256s each entry the fingerprint covers (typically all entries
that aren't excluded by the Gradle DSL). Total cost on a clean
device on Pixel 9 Pro: ~50–200 ms cold, ~5 ms warm (the decoded
fingerprint is cached for the process lifetime so the surrounding
`TelemetryCollector` can reuse it).

### Caveats

- **Library-only mode (no Gradle plugin) → INCONCLUSIVE.** Skipping
  the plugin omits the fingerprint asset, so the detector reports
  `status: "inconclusive"` with `inconclusive_reason: "asset_missing"`.
  Every other detector continues to work unchanged. See
  [Library-only mode](../README.md#library-only-mode-advanced) in
  the main README for when this is the right trade.
- **Decode-failure-as-finding.** Decode failures that look like
  attack (asset stripped, key class missing, blob encrypted with
  a different key, blob structurally corrupt) become CRITICAL
  findings of `status: "ok"`, not `INCONCLUSIVE`. These are
  signals worth reporting even if we can't run the rest of the
  comparison. Decode failures that look like CI / version skew
  (a newer plugin version producing a blob the AAR doesn't
  understand) become INCONCLUSIVE — that's a build bug, not an
  attack.

---

## `integrity.bootloader`

`attestation.key` reports what the TEE *claims*. On a device with
[Tricky Store](https://github.com/5ec1cff/TrickyStore) / LSPosed
installed, the AndroidKeyStore surface itself is hooked: the
attacker captures a clean attestation chain on a known-good boot
session and replays it on every subsequent keygen call.
`attestation.key` sees a well-formed chain, parses it, and
dutifully reports `device_locked = true` even though
`getprop ro.boot.flash.locked` shows the bootloader as unlocked.

`integrity.bootloader` raises the cost of that bypass with
orthogonal cross-checks. It runs a **second** attestation under a
fresh alias + nonce and compares it to `attestation.key`'s. On a
clean device it emits **zero findings** and costs one extra TEE
keygen (~80–500 ms TEE / ~0.5–4 s StrongBox), absorbed by the same
background pre-warm that runs `attestation.key`.

### Threat model

A cache-replay forgery struggles to satisfy these checks
simultaneously:

1. **Freshness across two attestations** — generates a *second*
   attestation under a fresh alias + nonce. Two consecutive
   keygens on the same boot session MUST produce different leaf
   SubjectPublicKeys (we asked for two distinct EC keys) and MUST
   embed two distinct attestation challenges (we sent two
   different nonces). A cache-replay forgery typically returns
   the same leaf for every keygen call.
2. **Challenge echo** — the leaf cert MUST embed the exact nonce
   we asked the TEE to attest. If it doesn't, the chain was
   minted for some other request.
3. **Leaf pubkey matches keystore key** — the leaf cert's
   SubjectPublicKey MUST equal the public key the AndroidKeyStore
   actually holds for our alias. A naive cached chain serves
   someone else's pubkey here.
4. **Chain structural validity** — every cert in the chain must
   verify against its issuer; the root must self-sign;
   intermediate validity windows must nest properly.
5. **StrongBox unexpectedly unavailable** — devices that should
   expose a StrongBox-class secure element MUST attest with
   security level `STRONG_BOX`. Triggers when EITHER the platform
   self-reports `FEATURE_STRONGBOX_KEYSTORE` OR the device
   matches the hardcoded Pixel-3+ denylist, AND the actual
   attestation comes back as `TRUSTED_ENVIRONMENT` or `SOFTWARE`.

### Finding kinds

| Finding kind                            | Subreason                            | Severity | Triggered when                                                                                                                              |
| --------------------------------------- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `bootloader_integrity_anomaly`          | `chain_empty`                        | high     | `attestation.key`'s chain has no certs                                                                                                      |
| `bootloader_integrity_anomaly`          | `chain_too_short`                    | high     | `attestation.key`'s chain has fewer than 2 certs (real attestation chains have leaf + ≥1 issuer)                                            |
| `bootloader_integrity_anomaly`          | `chain_signature_invalid`            | high     | A cert in the chain doesn't verify against its issuer's public key                                                                          |
| `bootloader_integrity_anomaly`          | `chain_root_not_self_signed`         | high     | The root cert doesn't self-sign                                                                                                             |
| `bootloader_integrity_anomaly`          | `challenge_not_echoed`               | high     | The leaf doesn't embed the nonce we asked the TEE to attest                                                                                 |
| `bootloader_integrity_anomaly`          | `freshness_pubkey_identical`         | high     | Two consecutive keygens (under different aliases) produced leaf certs with the same SubjectPublicKey                                        |
| `bootloader_integrity_anomaly`          | `freshness_challenge_identical`      | high     | Two consecutive keygens (with different nonces) produced leaf certs that echo the same attestation challenge                                |
| `bootloader_integrity_anomaly`          | `leaf_pubkey_mismatch`               | high     | The leaf cert's SubjectPublicKey doesn't match the public key the AndroidKeyStore actually holds for our alias                              |
| `bootloader_integrity_anomaly`          | `leaf_pubkey_unreadable`             | medium   | Defensive: leaf's pubkey couldn't be decoded for comparison                                                                                 |
| `bootloader_strongbox_unavailable`      | `strongbox_unexpectedly_unavailable` | medium   | Device advertises StrongBox capability — either via `PackageManager.FEATURE_STRONGBOX_KEYSTORE` or by being on the Pixel-3+ denylist — but the attestation came back at TEE / SOFTWARE security level |

> **Why no leaf-validity / leaf-serial / leaf-age checks?** Real
> Android KeyMint sets the attestation leaf cert's
> `notBefore = 1970-01-01`, `notAfter = 2048-01-01`, and
> `serialNumber = 1` for *every* attested key — these fields
> carry no per-keygen meaning, so checks against them would
> false-positive on every clean device. `integrity.bootloader`
> instead derives freshness signals from data the TEE *does*
> sign meaningfully: the embedded attestation challenge and the
> leaf SubjectPublicKey.

### Sample tripped JSON

```json
{
  "id": "integrity.bootloader",
  "status": "ok",
  "duration_ms": 312,
  "findings": [
    {
      "kind": "bootloader_strongbox_unavailable",
      "severity": "medium",
      "subject": "com.example.app",
      "message": "Device advertises StrongBox capability (platform=true, pixel_denylist=true) but TEE attestation came back at security level TrustedEnvironment — StrongBox surface may have been bypassed",
      "details": {
        "subreason": "strongbox_unexpectedly_unavailable",
        "verdict_authoritative": "false",
        "device_model": "Pixel 6 Pro",
        "attestation_security_level": "TrustedEnvironment",
        "strongbox_platform_available": "true",
        "strongbox_pixel_denylist_match": "true"
      }
    }
  ]
}
```

### Costs

One additional TEE keygen per process (~80–500 ms TEE / ~0.5–4 s
StrongBox). Cached for the process lifetime, same as
`attestation.key`. Pure cross-check functions (see `ChainValidator`)
on top of the two cached chains run in sub-millisecond.

### Caveats

- **Authority caveat.** Like `attestation.key`'s verdict finding,
  every `integrity.bootloader` finding carries
  `verdict_authoritative = "false"` in `details`. The library does
  not consider these signals authoritative — they are *advisory*.
  The authoritative verdict still comes from a backend that
  re-verifies `attestation.key`'s `cert_chain_b64` against
  Google's pinned attestation root + revocation list +
  fleet-wide correlation.
- **`status: "inconclusive"` modes.** Returns INCONCLUSIVE with
  reason `attestation_key_unavailable` if `attestation.key`
  hasn't cached a result yet, or with the same failure-reason
  vocabulary as `attestation.key`
  (`attestation_not_supported` / `keystore_error` /
  `keystore_unavailable`) if `integrity.bootloader`'s own keygen
  fails.

---

## `integrity.art`

`runtime.environment` catches *libraries* known to perform hooking
(Frida / Xposed / LSPosed / Substrate / Riru / Zygisk / Taichi).
It does not catch the *act* of a hook — a renamed, in-memory-only,
or custom hooker passes `runtime.environment` trivially.
`integrity.art` closes that gap by inspecting the ART internals
themselves and emitting a finding when something has tampered with
them, regardless of which framework (or non-framework) did the
tampering.

It runs **five orthogonal vectors**, each targeting a distinct
hooking technique:

| Vector | Targets                                                                                                                                                               | Catches                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**  | The `entry_point_from_quick_compiled_code_` slot of ~10 frozen Java methods (`System.currentTimeMillis`, `Object.hashCode`, `String.length`, …)                       | The primary tool every Xposed-family hooker (Xposed, EdXposed, LSPosed, YAHFA, Pine, SandHook, Whale) uses to redirect Java method execution. Also catches **Frida's mere attachment** to the process via the `Object#hashCode/getClass` `jit_cache → libart` drift signature. |
| **C**  | Eight watched JNIEnv function pointers — `GetMethodID`, `GetStaticMethodID`, `RegisterNatives`, `CallStaticIntMethod`, `CallObjectMethod`, `FindClass`, `NewObject`, `GetObjectClass` | The classic Frida-Java JNI hijack pattern: `JNIEnv->functions->GetMethodID` and friends rewritten to a Frida-allocated trampoline                                                                    |
| **D**  | The first 16 bytes of ~10 ART hot-path internal functions (`art::ArtMethod::Invoke`, `art::JNI<true>::CallStaticIntMethod`, `art_quick_invoke_stub`, …)               | Modern Frida `Interceptor.attach` — patches the *prologue* of ART internal functions so that hooking the slot or the function-table doesn't catch it                                                 |
| **E**  | The `entry_point_from_jni_` (`data_`) slot of the same ~10 frozen Java methods                                                                                        | Direct overwrites of the JNI bridge pointer for declared-`native` JDK methods. The bridge pointer is rewritten by some Xposed forks (Pine, Dobby) and by Frida-Java for native targets.              |
| **F**  | The `access_flags_` field of the same ~10 frozen Java methods, specifically the `ACC_NATIVE` (0x100) bit                                                              | Frida-Java's `cls.method.implementation = ...` for non-native methods. To redirect dispatch through the JNI bridge slot, Frida-Java flips `ACC_NATIVE` ON. Java methods do not become native at runtime under any benign code path — this is a binary, unambiguous tamper signal. |

Snapshots for all five vectors are captured **once**, at
`JNI_OnLoad` (the earliest moment we can run native code, before
any post-Application hook installer typically runs), and stored
in `mmap(MAP_ANONYMOUS|MAP_PRIVATE)` pages that are
`mprotect`'d to `PROT_NONE` between scans. Each snapshot's
SHA-256 hash lives in a second, separately-mapped page so an
attacker who manages to find and overwrite the snapshot can't
simultaneously update the hash to hide the tamper.

### Finding kinds

| Finding kind                                  | Vector | Severity | Triggered when                                                                                                                                                                              |
| --------------------------------------------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `art_method_entry_out_of_range`               | A      | high     | Live entry pointer lands outside libart, the boot OAT region, and the JIT cache. Catches the hook currently installed.                                                                     |
| `art_method_entry_drifted`                    | A      | high     | Live entry differs from the JNI_OnLoad snapshot AND the transition isn't a benign ART-internal one (libart→libart, libart→boot_oat, libart→jit_cache, boot_oat→boot_oat, jit_cache→jit_cache). Catches transient hooks AND Frida's bridge initialisation. |
| `art_baseline_tampered`                       | A      | high     | The mmap-protected snapshot page itself was modified between scans — direct attack on this detector's storage.                                                                             |
| `jni_env_table_out_of_range`                  | C      | high     | A watched `JNIEnv->functions->*` pointer lands outside libart's RX segment.                                                                                                                |
| `jni_env_table_drifted`                       | C      | high     | A watched JNIEnv pointer differs from the JNI_OnLoad snapshot.                                                                                                                              |
| `jni_env_baseline_tampered`                   | C      | high     | The mmap-protected JNIEnv snapshot page itself was modified.                                                                                                                                |
| `art_internal_prologue_drifted`               | D      | high     | The first 16 bytes of a watched ART internal function differ from the JNI_OnLoad snapshot. Catches `Interceptor.attach`-style inline hooks installed after our load.                       |
| `art_internal_prologue_baseline_mismatch`     | D      | medium   | Live prologue differs from the embedded per-API baseline. Lower severity because pre-`JNI_OnLoad` injection and unrecognised OEM ROMs are indistinguishable.                                |
| `art_internal_prologue_baseline_tampered`     | D      | high     | The mmap-protected inline-prologue snapshot page itself was modified.                                                                                                                       |
| `art_method_jni_entry_out_of_range`           | E      | high     | `entry_point_from_jni_` transitioned from a known region (libart / boot OAT) to unknown memory. Catches Frida's bridge install on any method.                                              |
| `art_method_jni_entry_drifted`                | E      | high     | `entry_point_from_jni_` value changed AND the registry says the method is declared `native` in the JDK. Catches Frida-Java even when both addresses classify as unknown (boot.art stub → bridge). |
| `art_method_jni_entry_baseline_tampered`      | E      | high     | The mmap-protected JNI-entry snapshot page itself was modified.                                                                                                                             |
| `art_method_acc_native_flipped_on`            | F      | high     | The `ACC_NATIVE` (0x100) bit went 0 → 1 on a registry method. Frida-Java fingerprint for non-native targets.                                                                                |
| `art_method_acc_native_flipped_off`           | F      | high     | The `ACC_NATIVE` bit went 1 → 0 on a method that was native at startup. Rare reverse-tamper.                                                                                                |
| `art_method_access_flags_baseline_tampered`   | F      | high     | The mmap-protected access-flags snapshot page itself was modified.                                                                                                                          |

### Threat model — what `integrity.art` catches and what it doesn't

`integrity.art` catches:

- **Post-`JNI_OnLoad` rewrites of `ArtMethod->entry_point_from_quick_compiled_code_`**
  for any of the 10 watched frozen methods (Vector A). This is
  the field Xposed, EdXposed, LSPosed, YAHFA, Pine, SandHook,
  and Whale all patch — the canonical "entry-point hook" attack.
- **Frida's mere presence** in the process (Vector A). Empirically
  on Pixel 6 Pro (API 36), Frida-Java's bridge initialisation
  causes `Object#hashCode` and `Object#getClass` to drift from
  `jit_cache` → `libart`. The drift filter reports both as
  `art_method_entry_drifted`. This means `integrity.art` can
  detect Frida before the user installs any application-level
  hook.
- **JNIEnv function-table tampering** for the 8 most commonly
  hijacked entries (Vector C). These pointers live in libart's
  read-only `.data.rel.ro` and never legitimately change.
- **Inline trampolines on ART internal functions** for the 10
  watched hot-path symbols (Vector D). The first 16 bytes are
  byte-compared against both an embedded per-Android-API baseline
  (catches pre-`JNI_OnLoad` injectors) and the JNI_OnLoad
  snapshot (catches post-load patches).
- **Direct `entry_point_from_jni_` overwrites** for declared-
  `native` JDK methods (Vector E). Catches the JNI bridge
  rewrites used by Pine / Dobby / SandHook native-method
  hookers and by Frida-Java for native targets.
- **`ACC_NATIVE` bit flips** for non-native JDK methods (Vector
  F). Catches `cls.method.implementation = ...` for the most
  common Frida-Java target type — but only when the target
  method is non-native and the bit was actually flipped (modern
  Frida-Java uses this technique for some target types and not
  others; see the [red-team README](../tools/red-team/README.md#what-frida-java-actually-changes)
  for the empirical observations).

`integrity.art` does *not* catch:

- **Frida-Java `cls.method.implementation = ...` on a JIT-resident
  non-native method whose bridge also lands in the JIT cache.**
  Empirically `String#length` exhibits this on Pixel 6 Pro: both
  the original entry and the Frida-Java bridge sit in the same
  `jit_cache` region, and our drift filter intentionally
  suppresses `jit_cache → jit_cache` transitions to avoid
  false-positives on benign ART JIT recompilation. The Frida
  attach itself is still detected via the `Object#hashCode`
  signal above, so a real Frida session is rarely fully
  invisible — but the per-method finding for this specific case
  is missed.
- **Early Zygisk injection of a frozen LSPosed module** that
  patched ART before the app's own native libraries loaded.
  Vector A's snapshot already reflects the hook, so the drift
  check passes; Vector D's `baseline_mismatch` partially
  compensates by flagging that a known-API prologue diverges,
  but on un-baselined OEM ROMs that's indistinguishable from
  "we don't have a baseline for this device" — which is why
  the finding is `medium`, not `high`.
- **Pure native libc hooks** (PLT/GOT redirects on `open`,
  `read`, etc., or libcurl-internal trampolines). Those stay
  with `runtime.environment`'s name-based detection —
  `integrity.art` is intentionally scoped to ART internals.
- **Side-channel hooks** that don't touch the watched ~50 fields
  across the five vectors. `integrity.art` is point-in-time: it
  audits the locations it knows about, not every byte in libart.
- **Attackers who can both forge the hash page and the values
  page** (a defeat of the self-protection). Mitigated by the
  hash page's randomized post-allocation spacing and the
  `PROT_NONE`-between-scans pattern, but not impossible.

### Sample tripped JSON

A backend sees this on a Pixel 6 Pro running with Frida attached
and a `cls.method.implementation = ...` hook on `String#length`
plus a direct `ACC_NATIVE` flip on the same method (the
`tools/red-team/frida-vector-f.js` exercise):

```json
{
  "id": "integrity.art",
  "status": "ok",
  "duration_ms": 4,
  "findings": [
    {
      "kind": "art_method_entry_drifted",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "ArtMethod entry pointer changed since JNI_OnLoad snapshot",
      "details": {
        "method": "java.lang.Object#hashCode",
        "live_address": "0x79836aa1e0",
        "snapshot_address": "0x48026970",
        "live_classification": "libart",
        "snapshot_classification": "jit_cache"
      }
    },
    {
      "kind": "art_method_entry_drifted",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "ArtMethod entry pointer changed since JNI_OnLoad snapshot",
      "details": {
        "method": "java.lang.Object#getClass",
        "live_address": "0x79836aa1e0",
        "snapshot_address": "0x480111e0",
        "live_classification": "libart",
        "snapshot_classification": "jit_cache"
      }
    },
    {
      "kind": "art_method_acc_native_flipped_on",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "ArtMethod ACC_NATIVE bit flipped ON since JNI_OnLoad — Java method now dispatches as native (canonical Frida-Java fingerprint)",
      "details": {
        "method": "java.lang.String#length",
        "snapshot_flags": "0x86780001",
        "live_flags": "0x86780101"
      }
    }
  ]
}
```

The first two `art_method_entry_drifted` findings are the
Vector A `jit_cache → libart` Frida-attach signature: Frida-Java's
bridge initialisation moves the entries of `Object#hashCode` and
`Object#getClass` from a JIT-cache resident body to a libart
dispatch stub, and our drift filter reports the cross-region
transition. `integrity.art` picks this up the moment Frida is in
the process, even before the user installs an application-level
hook.

The third finding is the Vector F `ACC_NATIVE` flip — `0x86780001 →
0x86780101` flips the `0x100` bit. Java methods do not
legitimately become native at runtime under any benign code path,
so this is a binary, unambiguous tamper signal.

Backends correlate `kind` + `details.method` (or `.function` /
`.symbol`) across the fleet to spot which methods get hooked
together — a strong fingerprint for a specific hooking framework
or campaign. The fifteen finding kinds map back to the five
vectors documented in the table above, so a backend that wants
per-vector dashboards can group by the `kind` prefix
(`art_method_entry_*` → Vector A, `jni_env_table_*` → Vector C,
`art_internal_prologue_*` → Vector D, `art_method_jni_entry_*` →
Vector E, `art_method_acc_native_*` → Vector F).

### Costs

~50 field reads + 5 SHA-256s on tiny buffers; ~15 ms on a Pixel
6 Pro at API 36. Adds ~20 KB to `libdicore.so`.

### Caveats

- **No verdict caching — by design.** Unlike most other
  detectors, `integrity.art` **deliberately does not memoize its
  verdict across `collect()` calls**. A cached per-process verdict
  would let any Frida / LSPosed / Zygisk attach that landed
  *after* the first collect — the common runtime-injection case —
  hide forever behind the frozen pre-attach result. The full scan
  is cheap enough that re-running on every `DI.collect()` is the
  right default. Consumers that need a stricter perf budget
  should rate-limit `DI.collect()` itself; `integrity.art` will
  not silently age its output.
- **Red-team harness.** The
  [`tools/red-team/`](../tools/red-team/README.md) folder ships
  six Frida scripts (one per vector plus the end-to-end
  Frida-Java hook test) that intentionally trigger each finding,
  plus a README documenting the expected `findings` for each
  script. Use it after a code change to verify `integrity.art`
  still fires.

---

## `attestation.key`

`attestation.key` is the only detector that talks to the device's
TEE / StrongBox directly. It requests an attested EC keypair and
parses the `KeyDescription` extension Google's KeyMint signs into
the leaf cert (`OID 1.3.6.1.4.1.11129.2.1.17`).

Its output lives in **two places**, on purpose:

- **`app.attestation`** (top of the report) — the **always-shipped
  evidence + advisory verdict**. Present on every report (when the
  device supports hardware attestation), even on perfectly clean
  devices. The JSON ships a compact actionable subset: a SHA-256
  correlation key for the chain (`chain_sha256`), the security
  level the chain came back at (`attestation_security_level` /
  `keymaster_security_level` — `StrongBox` / `TrustedEnvironment` /
  `Software` — plus a derived `software_backed` boolean that's
  `true` iff *either* level is `Software`, useful for one-key
  cohort filters on backends that don't want to OR two strings),
  Verified Boot state, `device_locked`, OS patch level, attested
  package + signer, and the Play-Integrity-shaped advisory
  (`verdict_device_recognition` / `verdict_app_recognition` /
  `verdict_reason`). A backend that needs an authoritative verdict
  MUST re-verify the **chain bytes** against Google's
  hardware-attestation root and the
  [attestation revocation list](https://android.googleapis.com/attestation/status)
  server-side. The library does not do this on-device by design —
  an attacker who controls userland could patch the on-device
  verifier out. `verdict_authoritative` is always `false`: the
  local verdict is for in-app UX gating; trust the re-verified
  chain for security decisions.

  > **Where are the chain bytes?** To keep the JSON wire format
  > compact and human-readable for open-source consumers, the raw
  > base64 chain (~5KB) and a handful of diagnostic fields
  > (`attestation_challenge_b64`, `attested_application_id_sha256`,
  > `verified_boot_key_sha256`, `keymaster_version`, `os_version`,
  > `vendor_patch_level`, `boot_patch_level`) are **not** in the
  > JSON by default. They live on the typed `AttestationReport`
  > Kotlin object — backend uploaders that need to ship the bytes
  > for authoritative re-verification read them off the typed
  > report directly:
  >
  > ```kotlin
  > // Inside any coroutine — the suspend collect() dispatches to
  > // Dispatchers.IO for you. Use collectBlocking() from a
  > // synchronous worker thread.
  > val report = DeviceIntelligence.collect(context)
  > val chainB64: String? = report.app.attestation?.chainB64
  > val chainSha: String? = report.app.attestation?.chainSha256
  > // Upload chainB64 alongside the JSON; chainSha256 lets the backend
  > // dedup and correlate across reports without parsing the chain.
  > ```

- **Detector findings** (`tee_integrity_verdict`) — emitted
  **only when the local verdict is degraded** (severity > LOW).
  On a clean device `attestation.key` contributes zero findings,
  matching the rest of the library's "no news is good news"
  pattern. The verdict's wire spellings mirror Play Integrity
  (`MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`,
  `MEETS_STRONG_INTEGRITY`) so backends already wired up to
  Play Integrity can consume them without a remapping table.

### Finding kinds

| Finding kind                      | Severity | Triggered when                                                                                              |
| --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `tee_integrity_verdict`           | varies   | The locally derived advisory verdict is degraded (severity > LOW). Severity tracks the verdict's own severity ladder, which combines hardware-backing, verified-boot state, bootloader-locked flag, OS patch age, and app-recognition cross-check. CRITICAL when the chain is software-backed OR app-recognition flagged a mismatch; HIGH when verified-boot is anything other than Verified; MEDIUM for patch-too-old / bootloader-unlocked; LOW (suppressed) otherwise. |
| `attestation_eat_format_detected` | low      | The leaf cert's KeyDescription extension (OID `1.3.6.1.4.1.11129.2.1.17`) carries **CBOR-EAT** bytes instead of the legacy ASN.1 `KeyDescription` SEQUENCE. KeyMint 200+ on Android 14+ (RKP-provisioned keys) can emit attestation in this format. Library-side parsed fields will be null on those leaves; backends must re-parse the raw chain bytes (`app.attestation.chain_b64`) server-side for full field-level data. Full on-device CBOR/EAT decoding is tracked as a follow-up minor. Heuristic detection only — checks for a CBOR major-type-5 (map) byte (`0xA0`–`0xBF`) at the start of the unwrapped extension content. |

### Sample tripped JSON

```json
{
  "id": "attestation.key",
  "status": "ok",
  "duration_ms": 95,
  "findings": [
    {
      "kind": "tee_integrity_verdict",
      "severity": "high",
      "subject": "com.example.app",
      "message": "TEE evidence indicates degraded device or app integrity (advisory; verify chain server-side)",
      "details": {
        "device_recognition": "MEETS_BASIC_INTEGRITY",
        "app_recognition": "RECOGNIZED",
        "bootloader_locked": "false",
        "verified_boot_state": "Unverified",
        "verdict_authoritative": "false",
        "reason": "boot_unverified"
      }
    }
  ]
}
```

### Costs

Hardware key attestation requires Android 9 (API 28), which is
also the library's `minSdk` floor — so on any device that runs
the SDK at all, the surface is available. Where keygen still
fails (rare; stripped AOSP, no-TEE emulator), `app.attestation`
is non-null with `unavailable_reason` populated and the parsed
fields all `null` — backends always see the same shape.
Cold-start cost (~80–500 ms TEE / ~0.5–4 s StrongBox) is absorbed
by the manifest-merged init provider on a background thread, so
user-facing `collect()` reads the cached chain in single-digit ms.

### Caveats

- **Authoritative chain verification belongs server-side.** The
  on-device library does not walk the cert chain to Google's
  pinned attestation root or check the revocation list. Backends
  MUST re-verify `app.attestation.chain_b64` server-side. The
  `verdict_*` fields are advisory-only.
- **Wire shape vs typed shape.** The JSON omits the heavier
  diagnostic fields (`chain_b64`, `attestation_challenge_b64`,
  `attested_application_id_sha256`, `verified_boot_key_sha256`,
  `keymaster_version`, `os_version`, `vendor_patch_level`,
  `bootPatchLevel`) to keep the wire format compact. Backends
  that need to do authoritative re-verification of the chain
  bytes read this typed object directly (see
  `AppContext.attestation`) rather than parsing them out of JSON.

---

## `runtime.environment`

`runtime.environment` watches for tampering signals that show up
inside our own process the moment something attaches to or injects
into us. Four orthogonal channels (debugger / `ro.debuggable`
mismatch / known hooker library mapped / RWX trampoline page),
all powered by a single `/proc/self/maps` read and a single
`/proc/self/status` read; result is cached for the process
lifetime (`integrity.art` is the explicit non-cached counterpart —
see [`integrity.art`](#integrityart)).

### Threat model

The four channels look for signals that show up inside our own
address space when an instrumentation framework is loaded:

- **Debugger / native tracer.** `Debug.isDebuggerConnected()` plus
  `/proc/self/status TracerPid != 0` — catches gdb / lldb /
  `frida-trace` / strace.
- **`ro.debuggable` mismatch.** The app's own `FLAG_DEBUGGABLE`
  bit disagrees with the system property `ro.debuggable`. Classic
  repackaging tell: an attacker re-signed our APK with the
  debuggable flag forced on, or a Zygisk hook is lifting the bit
  to attach.
- **Known hooker library.** `/proc/self/maps` lists a library
  whose name matches a known hooking-framework signature (Frida,
  Substrate, Xposed, LSPosed, Riru, Zygisk, Taichi).
- **RWX trampoline page.** A `rwxp` / `rwxs` mapping exists in
  the process. The Android loader, ART JIT (dual-mapping on API
  28+), and ordinary `.so` segments never produce RWX regions —
  this is the canonical fingerprint of an in-process hooking
  framework allocating an RWX page to host its method-redirect
  trampolines.
- **Frida 16+ Gum JIT attribution (refinement).** When the same
  RWX scan sees a `/memfd:jit-cache` mapping with `rwxp` perms
  AND region size >8 MB, the additional `frida_memfd_jit_present`
  finding fires. ART legitimately maps the same memfd path but
  only with `r-xp` / `r--p` perms — the `rwxp` combination is a
  Frida-only signature on Android. Backends that want a
  Frida-attribution signal can pivot on this kind directly
  instead of inspecting `rwx_memory_mapping`'s `details`.

### Finding kinds

| Finding kind                 | Severity | Triggered when                                                                                                                              |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `debugger_attached`          | high     | `Debug.isDebuggerConnected()` is true OR `/proc/self/status` reports a non-zero `TracerPid` (gdb / lldb / `frida-trace` / strace attached)  |
| `ro_debuggable_mismatch`     | high     | The app's own `FLAG_DEBUGGABLE` disagrees with the system's `ro.debuggable` property (classic repackaging tell, also a Zygisk fingerprint)  |
| `hook_framework_present`     | high     | A library matching a known hooking-framework signature is mapped into the process (Frida, Substrate, Xposed, LSPosed, Riru, Zygisk, Taichi) |
| `rwx_memory_mapping`         | high     | A read-write-executable page mapping exists in the process. The Android loader, ART JIT (dual-mapping on API 28+), and ordinary `.so` segments never produce `rwxp` / `rwxs` regions — this is the canonical fingerprint of an in-process hooking-framework trampoline page (LSPosed/YAHFA/SandHook/Pine/Whale/Frida agent/Substrate). The `details.likely_cause` field surfaces this attribution explicitly so backends don't have to know ART internals to interpret the finding. |
| `frida_memfd_jit_present`    | high     | A `/memfd:jit-cache` mapping is present with `rwxp` perms AND region size >8 MB — the signature of Frida 16+'s Gum JIT heap. ART legitimately maps `/memfd:jit-cache` but only with `r-xp` / `r--p` perms, so the `rwxp` combination is unambiguous on Android. Fires in addition to `rwx_memory_mapping` when the same region matches — the more specific kind lets backends pivot on Frida-only without inspecting `details`. One finding per scan, with per-region descriptors in `details.region_<i>` |

Hook-framework matches emit one finding per distinct framework
(canonical name in `details.framework`), so backends can triage
each one independently. RWX mappings emit a single finding with
up to 8 region descriptors in `details.region_*`; if there are
more, the last entry is a `... +N more` overflow marker.

### Sample tripped JSON

What a backend sees when an LSPosed module (or any in-process
hooker that allocates an RWX trampoline page) is loaded into the
app process:

```json
{
  "id": "runtime.environment",
  "status": "ok",
  "duration_ms": 1,
  "findings": [
    {
      "kind": "ro_debuggable_mismatch",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "Application debuggable flag disagrees with system ro.debuggable property",
      "details": {
        "app_debuggable_flag": "true",
        "ro_debuggable": "0"
      }
    },
    {
      "kind": "rwx_memory_mapping",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "Read-write-executable memory mapping detected — strong signature of an in-process hooking framework trampoline (LSPosed/YAHFA/SandHook/Frida agent/Substrate). The Android loader and ART JIT do not produce RWX pages on API 28+; this is the canonical fingerprint left behind when a hooker allocates an RWX page to host its method-redirect trampolines.",
      "details": {
        "region_count": "1",
        "likely_cause": "in-process hooking framework trampoline page (LSPosed / YAHFA / SandHook / Pine / Whale / Frida agent / Substrate)",
        "region_0": "7c5b681000-7c5b682000 [anon]"
      }
    }
  ]
}
```

The two findings are independent signals that often co-occur on a
Zygisk-based hooking setup (LSPosed, EdXposed, Riru, etc.):
`ro_debuggable_mismatch` is the Zygisk injection fingerprint
(Zygisk lifts the app's debuggable bit so it can attach), and
`rwx_memory_mapping` is the trampoline page the hooker allocated
to host its method-redirect stubs. A backend can correlate the two
to attribute the finding to a specific framework family without
needing `integrity.art`'s per-method forensics.

If `integrity.art` also fires on the same collect, prefer
`integrity.art`'s findings for attribution (they tell you exactly
*which* method was hooked); `runtime.environment` remains useful
as the "framework is loaded" headline signal even when the hooked
method is outside `integrity.art`'s frozen registry — the common
case for application-specific LSPosed modules.

### Costs

~2-5 ms total on a clean device (one `/proc` read, one short
status parse, plus the maps scan). Cached for the process
lifetime.

### Caveats

- **Always returns `status: "ok"`.** The only failure mode is the
  native bridge being unavailable, in which case the
  maps-dependent checks silently degrade to "no signal" rather
  than reporting the detector as inconclusive.
- **Name-based detection only.** A renamed, in-memory-only, or
  custom hooker passes `runtime.environment` trivially — that's
  what `integrity.art` exists to close.

---

## `runtime.root`

`runtime.root` covers the filesystem-, shell-, and installed-app-
level root signals that pair with `attestation.key`'s TEE-attested
`verified_boot_state`. The "cheap" channels (su binary, Magisk
artefact files, `test-keys` build tag, `which su`, root-manager
app) can be hidden by a sufficiently determined hide-module
(Magisk's DenyList, Shamiko, etc.) — so this layer alone is best
thought of as the "low-hanging fruit" layer. A device that trips
*only* these signals is a device whose owner did not bother to hide
the root.

Three additional channels close the most common hide-module bypass
paths. **Shamiko** — the LSPosed module that targeted-app-hides
Magisk — operates by unsharing the *per-process* mount namespace
of the target app. It cannot patch init (PID 1)'s namespace, and
it cannot un-bind the daemon's actively-held abstract Unix socket.
Hence:

- `magisk_in_init_mountinfo` reads `/proc/1/mountinfo` and trips
  on Magisk-named mounts. Shamiko-bypass.
- `magisk_daemon_socket_present` reads `/proc/self/net/unix` and
  trips on the `@magisk_daemon` abstract socket. Shamiko-bypass.
- `tls_trust_store_tampered` reads `/proc/self/mountinfo` and
  trips on a `tmpfs` over `/apex/com.android.conscrypt` — the
  MagiskTrustUserCerts technique. This one is CRITICAL because
  the signal is *active TLS interception enablement*, not just
  "the device is rooted".

Note that all three Shamiko-bypass channels read procfs paths
through `File.readText()`; on a denied EACCES (e.g. `hidepid=2`
locked-down ROMs that hide PID 1's namespace from non-root
processes) the read fails and the channel silently degrades to
"no signal" — we never escalate a read failure into a finding,
mirroring the same discipline the rest of the detector uses for
`File.exists()` returning `false` on EACCES.

### Finding kinds

| Finding kind                    | Severity | Triggered when                                                                                                                              |
| ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `su_binary_present`             | high     | An `su` binary exists at one of the canonical hardcoded paths or in any directory on `$PATH` (one finding per matching path)                |
| `magisk_artifact_present`       | high     | A Magisk-shipped file/dir exists OR `/proc/mounts` has a `magisk`-named entry (one finding per matching artifact, descriptor in `details.artifact`) |
| `test_keys_build`               | medium   | `ro.build.tags` reports `test-keys` (custom ROM, eng build, or hand-edited build.prop)                                                      |
| `which_su_succeeded`            | high     | `Runtime.exec("which su")` resolved to a binary not on the hardcoded path list (only run when no other `su` hits, ~30-80ms cost)            |
| `root_manager_app_installed`    | medium   | A known root-manager / Xposed-manager app is installed (one finding per matched package, name in `details.package_name`)                    |
| `magisk_in_init_mountinfo`      | high     | `/proc/1/mountinfo` (init's mount namespace) contains a `magisk`-named entry. Shamiko operates by unsharing the *per-process* mount namespace of the target app; it cannot patch init's namespace, so a hit here while `/proc/self/mountinfo` looks clean is a strong "Magisk + Shamiko is actively hiding from us" signal. One finding per matching line, mount-point in `details.artifact` |
| `magisk_daemon_socket_present`  | high     | `/proc/self/net/unix` lists the `@magisk_daemon` abstract Unix socket. The socket is bound in init's network namespace and is visible to every process in the namespace; Shamiko hides filesystem artefacts but cannot un-bind the daemon's actively-held socket |
| `tls_trust_store_tampered`      | critical | `/proc/self/mountinfo` shows a `tmpfs` bind-mount over `/apex/com.android.conscrypt`. This is the **MagiskTrustUserCerts** technique: the system TLS trust store has been swapped with one accepting user-installed roots, meaning any HTTPS the app makes is MITM-interceptable by whoever installed the cert (Burp / Charles / mitmproxy / etc.). The signal is *active TLS interception enablement*, not just "root tool present" — backends should treat as a hard block for sensitive flows |

### Sample tripped JSON

```json
{
  "id": "runtime.root",
  "status": "ok",
  "duration_ms": 12,
  "findings": [
    {
      "kind": "su_binary_present",
      "severity": "high",
      "subject": null,
      "message": "su binary present at canonical path",
      "details": { "path": "/system/bin/su" }
    },
    {
      "kind": "root_manager_app_installed",
      "severity": "medium",
      "subject": "com.topjohnwu.magisk",
      "message": "Known root-manager package installed",
      "details": { "package_name": "com.topjohnwu.magisk" }
    }
  ]
}
```

### Costs

~5–80 ms on a clean device (the upper bound is when channel 4
`Runtime.exec("which su")` runs because nothing else hit; channels
1, 2, 3, 5 are sub-ms each). Cached for the process lifetime.

### Caveats

- **`QUERY_ALL_PACKAGES` permission notice.** Package visibility
  for the `root_manager_app_installed` channel is provided by
  `android.permission.QUERY_ALL_PACKAGES`, declared in the
  library manifest. This permission is merged into every
  consuming app and is treated as a
  [restricted permission by Google Play](https://support.google.com/googleplay/android-developer/answer/10158779);
  consumers shipping to Play must justify it under one of the
  permitted use cases ("anti-malware / device security" is the
  relevant category for DeviceIntelligence-driven integrity
  telemetry). Consumers who cannot justify it can strip it via
  manifest-merger:

  ```xml
  <uses-permission
      android:name="android.permission.QUERY_ALL_PACKAGES"
      tools:node="remove" />
  ```

  `runtime.root` then silently degrades to channels 1-4
  (`su` binary, Magisk artifacts, `test-keys`, `which su`) — only
  the `root_manager_app_installed` channel is affected.

- **Cross-check with `attestation.key`.** Same defense-in-depth
  principle as the rest of the library: if `runtime.root` trips,
  pair it with the TEE-attested `verified_boot_state` from
  `app.attestation` for an authoritative cross-check. If
  `runtime.root` says "clean" but `verified_boot_state` is
  `Unverified`, the device is likely running a root tool that
  hides from filesystem-level checks.

---

## `runtime.emulator`

CPU-instruction-level emulator detector. Drives the per-ABI
native probe (`emu_probe_arm64.cpp` / `emu_probe_x86_64.cpp`) and
emits a single `running_on_emulator` finding when the native side
flagged a *decisive* signal. The probe reads architectural CPU
state (system registers on arm64, CPUID leaves on x86\_64) — these
can't change for the lifetime of a process, so the result is
cached.

### Threat model

QEMU / Goldfish / ranchu / Genymotion all emulate the architectural
state of an arm64 / x86_64 CPU but leak information that real
silicon doesn't: hypervisor-bit set in CPUID on x86_64, MRS
instruction echo behaviour on arm64, etc. The native probe knows
about each leak channel and decides per-architecture whether the
sum of signals is decisive enough to fire.

### Finding kinds

| Finding kind             | Severity | Triggered when                                                                              |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------- |
| `running_on_emulator`    | high     | The CPU-instruction probe's per-arch decision rule decided the process is running inside a hypervisor / QEMU |

The `details` map carries the raw per-channel signals (`cpuid_hv`,
`mrs_*`, etc.) for forensics; backends can pivot on them to
distinguish QEMU from VMware / Genymotion / cloud Android.

### Sample tripped JSON

```json
{
  "id": "runtime.emulator",
  "status": "ok",
  "duration_ms": 1,
  "findings": [
    {
      "kind": "running_on_emulator",
      "severity": "high",
      "subject": null,
      "message": "CPU-instruction probe indicates the process is running inside a hypervisor / QEMU",
      "details": {
        "cpuid_hv": "1",
        "vendor_signature": "GenuineIntel"
      }
    }
  ]
}
```

### Costs

Sub-millisecond. Reads a handful of CPU registers / CPUID leaves
once per process and caches the verdict.

### Caveats

- **Architectural state only.** The probe doesn't look at
  filesystem signals (`/system/lib/libc_malloc_debug_qemu.so`,
  goldfish device files, etc.) because those are easy to spoof
  and the architectural state is harder. Cohort
  `running_on_emulator` against `device.hardware ==
  "goldfish" / "ranchu"` from `DeviceContext` for a complementary
  filesystem-level signal.
- **`status: "ok"` with no findings on a real device** is the
  expected clean case. A native-bridge unavailability degrades
  to INCONCLUSIVE rather than emitting a false positive.

---

## `runtime.cloner`

App-cloner / multi-app-launcher detector. Drives three native
readers in `libdicore.so` (`cloner_probe.cpp`) that pull
kernel-truth values out of `/proc/self/{maps,mountinfo,status}`
via raw syscalls, then compares them against the corresponding
Java-level values that any cloner would have to spoof. A
disagreement IS the signal.

### Threat model

App-cloner frameworks (Parallel Space, Waxmoon, dual-app on
some OEM ROMs, Island, …) launch the host app inside a
sandboxed environment that forwards Android API calls to a
controlled context. They rewrite Java-level identity so the
inner app sees its expected `Context.packageName`,
`Process.myUid()`, etc., but the *kernel* still sees the truth:
the inner app's APK is mapped into the launcher's address
space, the data dir is mounted from a tmpfs / foreign source,
and the kernel-real UID belongs to the launcher.

### Finding kinds

| Finding kind                  | Severity | Triggered when                                                                                                                              |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `apk_path_mismatch`           | high     | A `*.apk` mapping in our address space does not carry our package name. Catches in-process sandboxes (Waxmoon, Parallel Space) whose host code is mmapped alongside ours |
| `data_dir_mount_invalid`      | high     | Either a tmpfs/foreign-source mount on `/data/.../<our pkg>`, OR our package is missing from the set of pkg names extractable from data-dir mount-points (catches the Waxmoon case where we inherit the launcher's mount namespace via its UID) |
| `uid_mismatch`                | high     | Kernel-real UID disagrees with `Process.myUid()`. Catches Java-level UID hooks (Frida / Riru / Xposed scripts)                              |

The three signals are independent; any subset may trip per run.

### Sample tripped JSON

```json
{
  "id": "runtime.cloner",
  "status": "ok",
  "duration_ms": 2,
  "findings": [
    {
      "kind": "apk_path_mismatch",
      "severity": "high",
      "subject": "io.ssemaj.sample",
      "message": "An APK mapped into our address space does not carry our package name (cloner host)",
      "details": {
        "expected_package": "io.ssemaj.sample",
        "foreign_apk": "/data/app/com.lbe.parallel-VqLcjP-y6Q==/base.apk"
      }
    }
  ]
}
```

### Costs

Sub-millisecond. Three short `/proc` reads + a string compare.
Cached for the process lifetime.

### Caveats

- **Read failures degrade silently.** EACCES, EOF, and parse
  errors silently degrade to "no signal" for that channel; we
  never escalate a read failure into a finding.
- **`status: "inconclusive"` only when the native bridge is
  unavailable** — every other failure mode is treated as "no
  signal".
