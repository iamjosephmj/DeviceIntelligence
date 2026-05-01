<h1 align="center">DeviceIntelligence</h1>

<p align="center">
  <strong>Open-source Android telemetry SDK for understanding the device ecosystem of your userbase.</strong><br/>
  APK integrity · key attestation · bootloader integrity · runtime tampering · root indicators · emulator probe · cloner detection · 8-layer native anti-hooking stack.<br/>
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
    id("io.ssemaj.deviceintelligence") version "0.5.0"
}
```

**Collect**

```kotlin
lifecycleScope.launch {
    val report = DeviceIntelligence.collect(context)
    val json   = DeviceIntelligence.collectJson(context)

    val signals = report.toIntegritySignals()
    if (IntegritySignal.HOOKING_FRAMEWORK_DETECTED in signals) { /* … */ }
}
```

`kotlinx-coroutines-android` is the only runtime dependency. For Java callers use `collectBlocking()`; for long-running observation use `observe()`.

## What it collects

| Detector             | id                       | What it observes                                                              |
|----------------------|--------------------------|-------------------------------------------------------------------------------|
| APK integrity        | `integrity.apk`          | APK bytes vs. the build-time fingerprint baked by the Gradle plugin           |
| Bootloader integrity | `integrity.bootloader`   | TEE-spoofing / cached-chain detection on `attestation.key`                    |
| ART integrity        | `integrity.art`          | In-process ART tampering across 5 vectors (Frida, Xposed, LSPosed, Pine, …)   |
| Key attestation      | `attestation.key`        | TEE / StrongBox attestation: Verified Boot, bootloader lock, OS patch level   |
| Runtime environment  | `runtime.environment`    | Debugger / ptrace / native integrity stack (text hash, GOT, injected libs, …) |
| Root indicators      | `runtime.root`           | `su` binary, Magisk artifacts, `test-keys`, root-manager apps                 |
| Emulator probe       | `runtime.emulator`       | CPU-instruction-level signals (arm64 MRS / x86_64 CPUID hypervisor bit)       |
| App cloner           | `runtime.cloner`         | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches         |

Each detector emits granular `Finding`s; the `IntegritySignal` mapper collapses ~40 finding kinds into 11 product-shaped verdicts (`HOOKING_FRAMEWORK_DETECTED`, `ROOT_INDICATORS_PRESENT`, …) for UI / feature-flag code.

> **Not a RASP.** It does not block sessions, kill processes, or interrupt any flow. It only observes. Build enforcement on the JSON your backend ingests; keep the policy off-device.

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
  "library_version": "0.5.0",
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
    "library_plugin_version": "0.5.0",
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

| Permission             | Required by                                         | Opt-in                                |
|------------------------|-----------------------------------------------------|---------------------------------------|
| `QUERY_ALL_PACKAGES`   | `runtime.root` `root_manager_app_installed` channel | Strip via `tools:node="remove"`       |
| `ACCESS_NETWORK_STATE` | `DeviceContext.vpnActive`                           | `enableVpnDetection.set(true)`        |
| `USE_BIOMETRIC`        | `DeviceContext.biometricsEnrolled`                  | `enableBiometricsDetection.set(true)` |

When you opt out, the field reports `null` (not `false`).

## Documentation

- [**`docs/DETECTORS.md`**](docs/DETECTORS.md) — full per-detector reference (threat model, finding kinds, sample tripped JSON, costs, caveats)
- [**`NATIVE_INTEGRITY_DESIGN.md`**](NATIVE_INTEGRITY_DESIGN.md) — design of the 8-layer (G0–G7) anti-hooking stack
- [**`tools/red-team/`**](tools/red-team/README.md) — Frida scripts that intentionally trip each `integrity.art` finding

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
