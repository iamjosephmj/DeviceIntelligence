<h1 align="center">DeviceIntelligence</h1>

<p align="center">
  <strong>Open-source Android telemetry SDK for understanding the device ecosystem of your userbase.</strong><br/>
  APK integrity · key attestation · bootloader integrity · runtime tampering · root indicators · emulator probe · cloner detection · runtime DEX-injection · 8-layer native anti-hooking stack.<br/>
  <em>Not a RASP. Not a kill-switch. Just structured, deterministic JSON your backend can analyze.</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <a href="https://jitpack.io/#iamjosephmj/DeviceIntelligence"><img alt="JitPack" src="https://jitpack.io/v/iamjosephmj/DeviceIntelligence.svg"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Android-3DDC84.svg?logo=android&logoColor=white">
  <img alt="Min SDK" src="https://img.shields.io/badge/minSdk-28-green.svg">
  <img alt="Kotlin" src="https://img.shields.io/badge/Kotlin-2.0-7F52FF.svg?logo=kotlin&logoColor=white">
</p>

<p align="center">
  <img src="docs/images/p9_clean_signals_findings.png" alt="Clean Pixel 9 Pro" width="32%"/>
  <img src="docs/images/p6_rooted_signals_card.png" alt="Rooted Pixel 6 Pro — Signals card" width="32%"/>
  <img src="docs/images/p6_rooted_findings_expanded.png" alt="Rooted Pixel 6 Pro — Findings card expanded" width="32%"/>
</p>

<p align="center">
  <em>Same release APK, three devices. Left — clean Pixel 9 Pro. Middle — Pixel 6 Pro running KernelSU + LSPosed, Signals card lifts findings into product-shaped verdicts. Right — Findings card sorted worst-first, tap to expand the diagnostic <code>details</code> map.</em>
</p>

---

## Why DeviceIntelligence

Most Android apps shipping device-tampering checks reach for one of:

- **Google Play Integrity API** — black-box, requires Google Play Services, can't run on AOSP/FOSS devices, doesn't tell you *why* a device is suspect.
- **A commercial RASP** — expensive, partly closed-source, opaque detection logic, vendor lock-in.
- **A simple root checker** (RootBeer, SafetyNetHelper) — covers maybe 20% of the threat surface a real attacker uses.

DeviceIntelligence sits in the gap. It's:

- **Fully open-source** (Kotlin + native C++) — every detection rule is auditable. No closed binary blobs.
- **Free-of-Google** — no Play Services dependency; works on AOSP, OpenGApps, GrapheneOS, CalyxOS, etc. Hardware key attestation still works on those builds because it's a Keymaster API call, not a Google API call.
- **Detection-rich** — covers the techniques real attackers actually use: Frida agents, Xposed/LSPosed/EdXposed, Pine, SandHook, YAHFA, Cydia Substrate, Magisk, Zygisk, Riru, Taichi, app cloners, and runtime DEX injection (`InMemoryDexClassLoader`/`DexClassLoader` payloads). 8 layers of in-process anti-hooking with circular-bypass design.
- **Privacy-first** — anonymous-by-construction analytics. SHA-256 of `ro.build.fingerprint` for `client_id`, no PII, no package names, no memory addresses on the wire.
- **Backend-agnostic** — emits one deterministic JSON. Send it to your own backend, Datadog, BigQuery, anywhere. No SDK tries to talk to a vendor cloud.

**Use it when** you need device-tampering evidence richer than Play Integrity's pass/fail bit, want server-side control of the policy decision, can't or won't take the Play Services dependency, or want to audit the detection logic rather than trust a vendor's claims.

**Don't use it when** you want a turnkey "block this user" decision baked into the SDK — that's not what this is. DeviceIntelligence reports facts; *your backend* decides what to do about them.

## Install

Distributed via [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence).

**`settings.gradle.kts`**

```kotlin
pluginManagement {
    repositories { maven("https://jitpack.io"); gradlePluginPortal(); google() }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "io.ssemaj.deviceintelligence") {
                useModule(
                    "com.github.iamjosephmj.DeviceIntelligence:" +
                        "deviceintelligence-gradle:${requested.version}"
                )
            }
        }
    }
}

dependencyResolutionManagement {
    repositories { google(); mavenCentral(); maven("https://jitpack.io") }
}
```

**`app/build.gradle.kts`**

```kotlin
plugins {
    id("io.ssemaj.deviceintelligence") version "1.0.0"
}
```

Ships native binaries for **`arm64-v8a`**, **`x86_64`**, and **`armeabi-v7a`** (32-bit ARM). On 32-bit devices, all detectors run except `integrity.art`, which reports `INCONCLUSIVE` because the underlying `ArtMethod` field-offset table is currently 64-bit-only.

## Quick start

Four entry points, pick the one that matches your use case.

**One-shot collect** — your app starts, you want one structured snapshot, you ship it to your backend.

```kotlin
lifecycleScope.launch {
    val report = DeviceIntelligence.collect(context)             // TelemetryReport
    val json   = DeviceIntelligence.collectJson(context)         // canonical JSON

    val signals = report.toIntegritySignals()
    if (IntegritySignal.HOOKING_FRAMEWORK_DETECTED in signals) {
        // Send to your backend, gate the action, raise a flag — your call.
    }
}
```

**Periodic observe** — long-running session, you want a fresh snapshot every N seconds (e.g. catch a Frida agent that attaches mid-flow).

```kotlin
DeviceIntelligence.observe(context, interval = 2.seconds)
    .onEach { report -> render(report) }
    .launchIn(lifecycleScope)
```

**Cumulative session observe** — same as `observe()` but accumulates findings across emissions. A transient hook that fires once and detaches stays visible with `stillActive=false`. Use this when your UI / backend correlation should never lose sight of a signal the moment it stops appearing.

```kotlin
DeviceIntelligence.observeSession(context, interval = 2.seconds)
    .onEach { session: SessionFindings ->
        render(session.findings)             // List<TrackedFinding>
        ship(session.toJson())               // canonical wire format
    }
    .launchIn(lifecycleScope)
```

Each `TrackedFinding` carries `firstSeenAtEpochMs`, `lastSeenAtEpochMs`, `observationCount`, and `stillActive` on top of the underlying `Finding`.

**Java / synchronous boundary** — for Java consumers, worker threads, JNI bridges.

```java
TelemetryReport report = DeviceIntelligence.collectBlocking(context);
String json = DeviceIntelligence.collectJsonBlocking(context);
```

`kotlinx-coroutines-android` is the only runtime dependency.

## What it collects

| Detector             | id                       | What it observes                                                              |
|----------------------|--------------------------|-------------------------------------------------------------------------------|
| APK integrity        | `integrity.apk`          | APK bytes vs. the build-time fingerprint baked by the Gradle plugin           |
| Bootloader integrity | `integrity.bootloader`   | TEE-spoofing / cached-chain detection on `attestation.key`                    |
| ART integrity        | `integrity.art`          | In-process ART tampering across 5 vectors (Frida, Xposed, LSPosed, Pine, …)   |
| Key attestation      | `attestation.key`        | TEE / StrongBox attestation: Verified Boot, bootloader lock, OS patch level   |
| Runtime environment  | `runtime.environment`    | Debugger / ptrace / native integrity stack (text hash, GOT, injected libs) + runtime DEX-injection (InMemoryDexClassLoader / DexClassLoader payloads) + Frida 16+ Gum memfd-JIT attribution |
| Root indicators      | `runtime.root`           | `su` binary, Magisk artifacts, `test-keys`, root-manager apps, Shamiko-bypass cross-checks (init mount-namespace + `@magisk_daemon` socket), MagiskTrustUserCerts TLS-trust-store MITM |
| Emulator probe       | `runtime.emulator`       | CPU-instruction-level signals (arm64 MRS / x86_64 CPUID hypervisor bit)       |
| App cloner           | `runtime.cloner`         | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches         |

Each detector emits granular `Finding`s; the `IntegritySignal` mapper collapses ~40 finding kinds into 11 product-shaped verdicts for UI / feature-flag code:

| `IntegritySignal`               | Meaning                                                                                                                |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `APK_TAMPERED`                  | APK on disk modified, repackaged, signer mismatch, or installer not allowlisted.                                       |
| `APK_FINGERPRINT_UNAVAILABLE`   | The build-time fingerprint asset is missing/corrupt — couldn't make a verdict either way.                              |
| `BOOTLOADER_INTEGRITY_FAILED`   | Hardware key-attestation chain has anomalies, or device claims StrongBox but attests at a lower level.                 |
| `TEE_ATTESTATION_DEGRADED`      | Local advisory verdict on the attestation chain came back below `MEETS_STRONG_INTEGRITY`, OR the leaf cert's KeyDescription extension is in CBOR/EAT format (KeyMint 200+) and field-level parsing is deferred to backend re-verification. |
| `HOOKING_FRAMEWORK_DETECTED`    | Active code-level hooking — Frida (incl. Frida 16+ Gum memfd-JIT attribution), Xposed/LSPosed/EdXposed, Pine, SandHook, Substrate, ART-internals tampering, runtime DEX injection, RWX trampolines, `.text` drift, GOT rewrites. |
| `INJECTED_NATIVE_CODE`          | Unknown post-baseline `.so` or anonymous executable mapping; precondition for hooking but not yet proof of one.        |
| `ROOT_INDICATORS_PRESENT`       | `su` binary, Magisk artifact, `test-keys` build, `which su` succeeds, root-manager app installed, Magisk visible in PID 1's mount namespace (Shamiko bypass), `@magisk_daemon` abstract socket bound, or a `tmpfs` over `/apex/com.android.conscrypt` (MagiskTrustUserCerts TLS-MITM enablement — treat as hard block). |
| `EMULATOR_DETECTED`             | CPU-instruction-level signals — arm64 MRS or x86_64 CPUID hypervisor bit.                                              |
| `APP_CLONED`                    | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches.                                                 |
| `DEBUGGER_ATTACHED`             | JVM debugger or ptrace tracer attached.                                                                                |
| `DEBUG_FLAG_MISMATCH`           | App's `FLAG_DEBUGGABLE` disagrees with `ro.debuggable`.                                                                |
| `HARDWARE_ATTESTED_USERSPACE_TAMPERED` | **Strongest single signal.** Hardware attestation reports `verifiedBootState=Verified` AND a userspace hook finding fires in the same report. Either TEE compromise or post-attestation injection (Magisk + Shamiko, etc.). Backends should treat as highest-confidence compromise signal. |

```kotlin
val report = DeviceIntelligence.collect(context).toIntegritySignalReport()
when {
    // Hardware-attested AND userspace-tampered = the highest-confidence
    // signal the SDK can produce. Treat as a hard block.
    IntegritySignal.HARDWARE_ATTESTED_USERSPACE_TAMPERED in report.signals -> hardBlock()
    IntegritySignal.HOOKING_FRAMEWORK_DETECTED in report.signals           -> denyPayment()
    IntegritySignal.ROOT_INDICATORS_PRESENT in report.signals              -> warnUser()
    IntegritySignal.EMULATOR_DETECTED in report.signals                    -> requireExtra2FA()
    else                                                                    -> allow()
}
report.evidence[IntegritySignal.HOOKING_FRAMEWORK_DETECTED]?.forEach { finding ->
    log.info("hook detected — kind=${finding.kind} subject=${finding.subject}")
}
```

> **Not a RASP.** It does not block sessions, kill processes, or interrupt any flow. It only observes. Build enforcement on the JSON your backend ingests; keep the policy off-device.

## Validated against

DeviceIntelligence ships its own offensive verification harnesses — Frida scripts and a real LSPosed module that intentionally trip each detector. Detection isn't claimed; it's *verified* against the same tools an attacker would use, on real hardware (Pixel 6 Pro running KernelSU + LSPosed; secondary Pixel 9 Pro for clean baseline).

**Cross-OEM stability.** Beyond the per-detector verification on Pixels, `collect()` / `observe()` / `observeSession()` have been validated for runtime stability across [Sauce Labs](https://saucelabs.com/)' real-device farm — every Android 11+ (API 30–36) device in the farm, spanning the major OEM forks (Samsung One UI, Xiaomi HyperOS / MIUI, Vivo OriginOS, Honor MagicOS, OPPO ColorOS, OnePlus OxygenOS, Motorola, plus AOSP-equivalent Pixels). "Stability" here means: the native lib loads, every detector runs to completion, the JSON parses, no crashes on any tested device. Attack-scenario coverage (LSPosed / Frida actually firing detections) is verified on the Pixel 6 Pro reference rig.

**Cross-ABI stability.** All three native ABIs the AAR ships have been runtime-validated in the same Sauce Labs sweep:

| ABI            | Status                                                        |
| -------------- | --------------------------------------------------------------|
| `arm64-v8a`    | full coverage — every detector works                          |
| `x86_64`       | full coverage — every detector works                          |
| `armeabi-v7a`  | runtime-stable since 0.8.0 (validated on Sauce Labs 32-bit ARM devices). Every detector works EXCEPT `integrity.art`, which reports `INCONCLUSIVE` because the underlying `ArtMethod` field-offset table is 64-bit-only. Characterising 32-bit ART struct layouts is tracked as a future minor-version research task. |

| Surface                          | Validated with                                                                                       | Status |
|----------------------------------|------------------------------------------------------------------------------------------------------|--------|
| ART method-hook vectors A–F      | `tools/red-team/frida-vector-{a,c,d,e,f}.js` — 5 independent JNI-level Frida scripts                 | shipped |
| Frida-Java's `cls.method.implementation` | `tools/red-team/frida-vector-frida-java.js`                                                  | shipped |
| LSPosed Java-side method hooks   | `samples/lsposed-tester` — real LSPosed module installs hooks; StackGuard + StackWatchdog catch them | shipped |
| Runtime DEX injection (CTF Flag 1) | LSPosed-driven `InMemoryDexClassLoader` + disk-backed `DexClassLoader` from `/data/local/tmp/`     | shipped (0.6.0) |
| Pre-baseline DEX injection (Zygisk timing) | `samples/lsposed-tester` `EarlyDexInjectionHook` — synchronous inject in `handleLoadPackage`  | shipped via `unattributable_dex_at_baseline` (0.6.0) |
| Newer hook frameworks (Dobby/Whale/YAHFA/FastHook/il2cpp-dumper) | `tools/red-team/maps-newer-frameworks.js` — Frida `prctl(PR_SET_VMA_ANON_NAME)` page renaming | shipped (0.9.0) |
| Hardware attestation × userspace tampering correlation | composes existing detector findings — JVM unit tests + Pixel 6 Pro live data | shipped (1.0.0) |
| Magisk + Shamiko hide-module bypass | `/proc/1/mountinfo` cross-check (init namespace can't be unshared per-process) + `@magisk_daemon` abstract Unix socket via `/proc/self/net/unix` — JVM unit tests with hand-crafted procfs fixtures. Finding kinds: `magisk_in_init_mountinfo`, `magisk_daemon_socket_present` | shipped (1.x) |
| MagiskTrustUserCerts TLS-trust-store MITM | `tmpfs` bind-mount over `/apex/com.android.conscrypt` in `/proc/self/mountinfo` — JVM unit tests, CRITICAL severity (active TLS interception, not just root presence). Finding kind: `tls_trust_store_tampered` | shipped (1.x) |
| Frida 16+ Gum memfd-backed JIT | `/memfd:jit-cache` + `rwxp` + region size >8 MB pattern in `/proc/self/maps` — JVM unit tests; fires alongside the generic `rwx_memory_mapping` for backend Frida-attribution pivot. Finding kind: `frida_memfd_jit_present` | shipped (1.x) |
| EAT/CBOR attestation format detection | `KeyDescriptionParser` heuristic: when legacy ASN.1 parse fails AND the unwrapped extension starts with a CBOR map byte (`0xA0`–`0xBF`), emits `attestation_eat_format_detected` (LOW) so backends know parsed fields need server-side re-verification. Full CBOR-EAT field-level parsing tracked for a follow-up minor | shipped — format detection only (1.x) |
| Real Zygisk module               | TBD — see [`tools/red-team/CTF_ROADMAP.md`](tools/red-team/CTF_ROADMAP.md)                            | planned |
| Samsung Knox warranty-bit parsing | Samsung Knox attestation extension OID prefix is detected on the leaf, but warranty-bit byte parsing requires on-device Samsung validation tracked for a follow-up minor | planned |

Full step-by-step validation runbook for the Pixel 6 Pro: [`tools/red-team/FLAG1_RUNBOOK.md`](tools/red-team/FLAG1_RUNBOOK.md).

## Analytics

DeviceIntelligence ships anonymous device-hardware telemetry from the
native runtime to help improve detector accuracy across the long tail
of OEM devices. **Enabled by default.**

**To opt out**, in your `app/build.gradle.kts`:

```kotlin
deviceintelligence {
    disableAnalytics.set(true)
}
```

When disabled, the plugin injects a manifest `<meta-data>` flag the
native layer reads at startup; no background threads are started and
no HTTP calls are made. The `INTERNET` permission declared by the AAR
has no runtime effect (most apps already declare it for their own
network usage; the manifest merger produces no duplicate).

**What's collected**: ABI, API level, manufacturer, model, SoC name,
CPU vendor (from the emulator probe), ART / native-integrity result
codes, mount filesystem type names, loaded library basenames.

**Never collected**: package names, certificate hashes, memory
addresses, file paths, account / device / user identifiers, or any
app-specific data. `client_id` is a one-way SHA-256 of
`ro.build.fingerprint` and cannot be reversed to any user or device.

## JSON contract

`DeviceIntelligence.collectJson(context)` returns a single deterministic
document. The shape is stable across releases that share the same
`schema_version` (currently `2`). For every `Finding`, the fields
`kind` / `severity` / `subject` / `message` are stable; `details` is
opaque diagnostic data — useful for forensics, but its keys may change
between releases without a `schema_version` bump, so don't key on them
server-side.

**`status` vs `findings`** answer different questions. `status`
(`ok` / `inconclusive` / `error`) means "did the detector run?";
`findings[]` means "what did it see?". A rooted device looks like
`status: "ok"` plus a non-empty `findings[]`. Drive your "device looks
tampered" decision off `summary.detectors_with_findings`, not `status`.

**Per-collect vs cumulative session.** `collectJson()` and
`TelemetryReport.toJson()` emit one snapshot of the moment the
collect ran. `SessionFindings.toJson()` (from `observeSession`) emits
a cumulative session view — same wire shape per finding plus
`first_seen_at_epoch_ms` / `last_seen_at_epoch_ms` /
`observation_count` / `still_active`, with a `latest_report_summary`
correlation block. Both share `schema_version`; pick whichever
matches your backend's correlation model.

<details>
<summary><b>Full clean-device report (click to expand)</b></summary>

Captured live from a clean Pixel 9 Pro. Locale, timezone, install
timestamps, `vpn_active`, `boot_count`, and APK random suffixes were
swapped for generic values; everything else (StrongBox-backed
attestation, Tensor G4 SoC, Mali GPU, 120Hz panel, GMS signer SHA) is
the unmodified real value. For tripped-detector examples, see
[`docs/DETECTORS.md`](docs/DETECTORS.md).

```json
{
  "schema_version": 2,
  "library_version": "1.0.0",
  "collected_at_epoch_ms": 1777400000000,
  "collection_duration_ms": 8325,
  "device": {
    "manufacturer": "Google",
    "model": "Pixel 9 Pro",
    "sdk_int": 36,
    "abi": "arm64-v8a",
    "fingerprint": "google/caiman/caiman:16/CP1A.260405.005/15001963:user/release-keys",
    "total_ram_mb": 15583,
    "cpu_cores": 8,
    "screen_density_dpi": 480,
    "screen_resolution": "1280x2856",
    "has_fingerprint_hw": true,
    "has_telephony_hw": true,
    "sensor_count": 41,
    "boot_count": 142,
    "vpn_active": false,
    "strongbox_available": true,
    "brand": "google",
    "board": "caiman",
    "hardware": "caiman",
    "product": "caiman",
    "device": "caiman",
    "bootloader_version": "ripcurrentpro-16.4-14791556",
    "radio_version": "g5400c-251201-260127-B-14784805,g5400c-251201-260127-B-14784805",
    "build_host": "67911e6f684b",
    "build_user": "android-build",
    "build_type": "user",
    "build_tags": "release-keys",
    "build_time_epoch_ms": 1773135125000,
    "supported_abis_all": ["arm64-v8a"],
    "soc_manufacturer": "Google",
    "soc_model": "Tensor G4",
    "gl_es_version": "3.2",
    "egl_implementation": "mali",
    "default_locale": "en-US",
    "system_locales": ["en-US"],
    "timezone_id": "America/Los_Angeles",
    "timezone_offset_minutes": -480,
    "auto_time_enabled": true,
    "auto_time_zone_enabled": true,
    "display_refresh_rate_hz": 120.0,
    "display_supported_refresh_rates_hz": [1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 24.0, 30.0, 40.0, 60.0, 120.0],
    "display_hdr_types": ["HDR10", "HLG", "HDR10_PLUS"],
    "device_secure": true,
    "biometrics_enrolled": true,
    "adb_enabled": false,
    "developer_options_enabled": false,
    "battery_present": true,
    "battery_technology": "Li-ion",
    "battery_health": "good",
    "battery_plug_type": "none",
    "thermal_status": "none",
    "boot_epoch_ms": 1776800000000,
    "play_services_availability": "success",
    "play_services_version_code": 261533035,
    "play_store_version_code": 85101930,
    "gms_signer_sha256": "5f2391277b1dbd489000467e4c2fa6af802430080457dce2f618992e9dfb5402"
  },
  "app": {
    "package_name": "io.ssemaj.sample",
    "apk_path": "/data/app/.../io.ssemaj.sample-.../base.apk",
    "installer_package": null,
    "signer_cert_sha256": ["a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4"],
    "build_variant": "debug",
    "library_plugin_version": "1.0.0",
    "first_install_epoch_ms": 1775000000000,
    "last_update_epoch_ms": 1777300000000,
    "target_sdk_version": 36,
    "install_source": {
      "installing_package": null,
      "originating_package": null,
      "initiating_package": "com.android.shell"
    },
    "signer_cert_validity": [
      { "not_before_epoch_ms": 1771714645000, "not_after_epoch_ms": 2717794645000 }
    ],
    "attestation": {
      "chain_sha256": "dd12ccf2a857860f3712b45bcfebb7b917d4e0b9187cca0d0e50e9b119f5c9b8",
      "chain_length": 5,
      "attestation_security_level": "StrongBox",
      "keymaster_security_level": "StrongBox",
      "software_backed": false,
      "verified_boot_state": "Verified",
      "device_locked": true,
      "os_patch_level": 202604,
      "attested_package_name": "io.ssemaj.sample",
      "attested_signer_cert_sha256": ["a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4"],
      "verdict_device_recognition": "MEETS_BASIC_INTEGRITY,MEETS_DEVICE_INTEGRITY,MEETS_STRONG_INTEGRITY",
      "verdict_app_recognition": "RECOGNIZED",
      "verdict_reason": null,
      "verdict_authoritative": false,
      "unavailable_reason": null
    }
  },
  "detectors": [
    { "id": "integrity.apk",         "status": "ok", "duration_ms": 841,  "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "integrity.bootloader",  "status": "ok", "duration_ms": 243,  "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "integrity.art",         "status": "ok", "duration_ms": 4,    "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "attestation.key",       "status": "ok", "duration_ms": 495,  "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "runtime.environment",   "status": "ok", "duration_ms": 5525, "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "runtime.root",          "status": "ok", "duration_ms": 458,  "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "runtime.emulator",      "status": "ok", "duration_ms": 0,    "inconclusive_reason": null, "error_message": null, "findings": [] },
    { "id": "runtime.cloner",        "status": "ok", "duration_ms": 0,    "inconclusive_reason": null, "error_message": null, "findings": [] }
  ],
  "summary": {
    "total_findings": 0,
    "findings_by_severity": { "low": 0, "medium": 0, "high": 0, "critical": 0 },
    "findings_by_kind": {},
    "detectors_with_findings": [],
    "detectors_inconclusive": [],
    "detectors_errored": []
  }
}
```

</details>

A clean device emits empty `findings[]` everywhere and
`summary.total_findings: 0`. You can alert on `total_findings > 0`
server-side without parsing each detector individually.

## Try the sample

```sh
git clone https://github.com/iamjosephmj/DeviceIntelligence.git
cd DeviceIntelligence
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

## Permissions

| Permission             | Required by                                         | Default | Opt-out / opt-in                       |
|------------------------|-----------------------------------------------------|---------|----------------------------------------|
| `INTERNET`             | Anonymous analytics drain (see [Analytics](#analytics)) | on    | `disableAnalytics.set(true)`           |
| `QUERY_ALL_PACKAGES`   | `runtime.root` `root_manager_app_installed` channel | on      | Strip via `tools:node="remove"`        |
| `ACCESS_NETWORK_STATE` | `DeviceContext.vpnActive`                           | off     | `enableVpnDetection.set(true)`         |
| `USE_BIOMETRIC`        | `DeviceContext.biometricsEnrolled`                  | off     | `enableBiometricsDetection.set(true)`  |

When you opt out of `vpnActive` / `biometricsEnrolled`, the field
reports `null` (not `false`).

## Documentation

- [**`docs/DETECTORS.md`**](docs/DETECTORS.md) — full per-detector reference (threat model, finding kinds, sample tripped JSON, costs, caveats)
- [**`NATIVE_INTEGRITY_DESIGN.md`**](NATIVE_INTEGRITY_DESIGN.md) — design of the 8-layer (G0–G7) anti-hooking stack
- [**`CHANGELOG.md`**](CHANGELOG.md) — version history from 0.5.2 → 1.0.0 with wire-format impact notes per release
- [**`SECURITY.md`**](SECURITY.md) — vulnerability disclosure process, response SLOs, supported-versions policy
- [**`tools/red-team/`**](tools/red-team/README.md) — Frida scripts that intentionally trip each `integrity.art` finding (Vectors A/C/D/E/F + Frida-Java)
- [**`tools/red-team/CTF_ROADMAP.md`**](tools/red-team/CTF_ROADMAP.md) — capture-the-flag roadmap of every detection technique on the backlog (Flag 1 — DEX injection — captured 0.6.0; Flag 2 — newer hook frameworks — captured 0.9.0; Flag 5 — attestation × runtime correlation — captured 1.0.0)
- [**`tools/red-team/FLAG1_RUNBOOK.md`**](tools/red-team/FLAG1_RUNBOOK.md) — Pixel 6 Pro on-device validation runbook for the Flag 1 DEX-injection detector
- [**`samples/lsposed-tester/`**](samples/lsposed-tester/) — real LSPosed module that drives runtime DEX injection against the sample app, used to verify the detector against production attacker tooling rather than just Frida

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
