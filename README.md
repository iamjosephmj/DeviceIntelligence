<h1 align="center">DeviceIntelligence</h1>

<p align="center">
  <strong>An open-source Android telemetry SDK for understanding the device ecosystem of your userbase.</strong><br/>
  APK integrity · hardware-backed key attestation · bootloader integrity · runtime tampering · root indicators · emulator probe · app-cloner detection.<br/>
  <em>Not a RASP. Not a kill-switch. Just structured, deterministic facts your backend can analyze.</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <a href="https://jitpack.io/#iamjosephmj/DeviceIntelligence"><img alt="JitPack" src="https://jitpack.io/v/iamjosephmj/DeviceIntelligence.svg"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Android-3DDC84.svg?logo=android&logoColor=white">
  <img alt="Min SDK" src="https://img.shields.io/badge/minSdk-28%20(Android%209.0)-green.svg">
  <img alt="Kotlin" src="https://img.shields.io/badge/Kotlin-2.0-7F52FF.svg?logo=kotlin&logoColor=white">
  <img alt="Schema" src="https://img.shields.io/badge/wire_schema-v1-orange.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-pre--1.0-yellow.svg">
</p>

---

DeviceIntelligence is a **device-intelligence telemetry SDK** for Android. It
collects structured facts about the runtime environment of your app — APK
integrity, in-process tampering, hardware-backed device attestation, bootloader
state, root indicators, emulator characteristics, and app-cloner signals — and
hands them back as a single deterministic JSON report you can ship to your
backend for ecosystem analysis.

> **This is NOT a RASP (Runtime Application Self-Protection) tool.** It does
> not block sessions, kill processes, lock data, prompt the user, or interrupt
> any flow. It only observes.
>
> The intended use case is **ecosystem analysis**: answering questions like
> *"what fraction of my MAU is on rooted devices?"*, *"how many sessions
> originate from emulators?"*, *"what's the bootloader-lock distribution across
> my fleet?"*, *"which hooking frameworks show up in my install base, and on
> which device models?"*. Your backend ingests the JSON, aggregates it across
> sessions, and surfaces the patterns. If you later decide to act on a specific
> signal, the policy lives in your backend (or in your in-app code that reads
> the report) — never inside this library. See
> [Why telemetry, not RASP?](#why-telemetry-not-rasp) below.

```text
DeviceIntelligence.collect(context).toJson()
   ↓
{ schema_version, library_version, device, app, detectors[], summary }
   ↓
your backend / data warehouse  →  dashboards, cohorts, fraud signals
```

## Table of contents

- [Why DeviceIntelligence?](#why-deviceintelligence)
  - [Why telemetry, not RASP?](#why-telemetry-not-rasp)
- [What it collects](#what-it-collects)
- [Quickstart](#quickstart)
- [Output shape](#output-shape)
- [Stable contract](#stable-contract)
  - [`status` vs `findings` — read this once](#status-vs-findings--read-this-once)
- [Detector deep dives](#detector-deep-dives)
  - [F14 — Hardware key attestation](#hardware-key-attestation-f14-and-appattestation)
  - [F15 — Bootloader integrity](#bootloader-integrity-f15)
  - [F16 — Runtime environment](#runtime-environment-f16)
  - [F17 — Root indicators](#root-indicators-f17)
- [Permissions](#permissions)
- [Performance, threading, caching](#performance-threading-caching)
- [The sample app](#the-sample-app)
- [Building from source](#building-from-source)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Prior art and acknowledgments](#prior-art-and-acknowledgments)
- [License](#license)

## Why DeviceIntelligence?

DeviceIntelligence is for product, security, and trust-and-safety teams that
want **visibility into the device ecosystem of their userbase** without taking
the policy / enforcement risk of a RASP. Most Android integrity stories
collapse to one of three things — **Play Integrity** (opaque server-verified
verdicts, requires Google Mobile Services, sees one session at a time),
**RASP / commercial in-app-protection SDKs** (decide on-device whether to crash
the app, kill data, or block the session — fast to ship, brittle to maintain,
hostile to legitimate edge-case users), or **a hand-rolled mix of `getprop`
calls and one-off `/proc` reads** that grow into spaghetti and never get
audited.

DeviceIntelligence sits in a different spot from all three:

| | Play Integrity | RASP / in-app-protection SDKs | RootBeer-style libs | **DeviceIntelligence** |
|---|---|---|---|---|
| Open source | No | No | Yes | **Yes (Apache 2.0)** |
| Works without Google Mobile Services | No | Yes | Yes | **Yes** |
| Hardware-backed attestation evidence | Yes (verdict only) | Sometimes | No | **Yes (raw chain → backend)** |
| Multi-layer (defense-in-depth) | Single verdict | Yes | Single signal | **7 orthogonal detectors** |
| Honest about what it can't prove | Mixed | Rarely | No | **Yes — every signal documents its bypass model** |
| Stable, versioned wire format | Yes | Vendor-specific | No | **Yes (`schema_version: 1`)** |
| Decides on-device whether to block / crash / lock | No (server-verified verdict) | **Yes (this is the point)** | N/A (you decide) | **No — explicitly never** |
| Designed for fleet-wide ecosystem analysis | Per-session | No | No | **Yes (deterministic JSON for warehousing)** |

DeviceIntelligence will not give you a single magic boolean. It will give you a
structured, deterministic report — the same shape every time, suitable for
warehousing — that you can correlate server-side with whatever else you know
about the user / session / cohort. Pair it with Play Integrity if you have it
(the two are complementary); pair it with a RASP if you have one (DeviceIntelligence
gives you the *visibility* the RASP doesn't, the RASP gives you the *enforcement*
DeviceIntelligence won't).

### Why telemetry, not RASP?

The library deliberately never decides whether to block a session, prompt the
user, log the user out, lock data, or anything else with on-device side
effects. Three reasons:

1. **No individual signal is authoritative.** Every check is designed around a
   clear bypass model (documented per-detector in the deep-dive sections
   below). Useful telemetry signals become *valuable* through fleet-wide
   correlation on a backend you control — not through brittle on-device
   "if rooted then crash" branches.
2. **On-device policy is the brittle part of every RASP.** An attacker who
   controls userland can patch out `if (tampered) System.exit()`. They cannot
   patch out the JSON your backend already received. Keeping policy off-device
   keeps the library's attack surface tiny.
3. **Ecosystem visibility is its own product.** Even if you never block a
   single session, knowing that 3% of your MAU runs on rooted devices, that
   emulator traffic spikes 4x during a promo campaign, or that one specific
   APK build of yours is being repackaged and re-signed in the wild — that's
   product intelligence you can act on (campaign targeting, fraud-rule
   tuning, support-volume planning) without ever touching enforcement.

If you want enforcement, build it where it belongs: in your backend, on top of
the JSON DeviceIntelligence ships you. Or pair this library with a separate
RASP and let each layer do what it's good at.

## What it collects

| Detector              | id                            | What it observes                                                                                 |
| --------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------ |
| APK integrity         | `F10.apk_integrity`           | APK bytes vs. the build-time fingerprint baked by the Gradle plugin                              |
| Emulator probe        | `F12.emulator_probe`          | CPU-instruction-level signals (arm64 MRS / x86\_64 CPUID hypervisor bit)                         |
| App cloner            | `F13.cloner_probe`            | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches                            |
| Key attestation       | `F14.key_attestation`         | TEE / StrongBox attestation: Verified Boot state, bootloader lock, OS patch level                |
| Bootloader integrity  | `F15.bootloader_integrity`    | Cross-checks F14's chain against a second attestation to surface TEE spoofing / cached chains    |
| Runtime environment   | `F16.runtime_environment`     | In-process tampering: debugger / native tracer attached, `ro.debuggable` mismatch, hooking framework loaded (Frida / Xposed / LSPosed / Substrate / Riru / Zygisk / Taichi), RWX memory mappings |
| Root indicators       | `F17.root_indicators`         | `su` binary on disk (PATH walk + hardcoded paths), Magisk artifacts (filesystem + `/proc/mounts`), `ro.build.tags = test-keys`, `which su` fallthrough, known root-manager apps installed |

Every detector is independent. Adding a new one is a single line in
`TelemetryCollector` and a single class implementing the internal `Detector`
interface — no public-API changes, no JSON-serializer changes, no policy changes.

## Quickstart

> Distributed via [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence).
> One plugin, one version. The plugin auto-applies the matching runtime AAR for
> you, so there's no second `implementation(...)` line to keep in sync.

### Run the sample app in 30 seconds

```sh
git clone https://github.com/iamjosephmj/DeviceIntelligence.git
cd DeviceIntelligence
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

You'll see a card-based viewer that re-runs every detector on demand and lets you
copy the canonical JSON to your clipboard. On a clean device, every detector
reports `status: "ok"` with `findings: []`.

### Add it to your own app

Replace `0.1.0` below with the latest tag on
[the JitPack page](https://jitpack.io/#iamjosephmj/DeviceIntelligence).

**`settings.gradle.kts`** — declare the JitPack repo and map the plugin id to its
JitPack-published module coordinate. The 5-line `eachPlugin` block is the
[standard JitPack-Gradle-plugin pattern](https://docs.jitpack.io/building/#gradle-plugins);
it's needed because Gradle's plugin-marker resolution lives at a different
group (`io.ssemaj.deviceintelligence`) than where JitPack serves artifacts
(`com.github.iamjosephmj.DeviceIntelligence`):

```kotlin
pluginManagement {
    repositories {
        maven("https://jitpack.io")
        gradlePluginPortal()
        google()
    }
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
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}
```

**`app/build.gradle.kts`** — apply the plugin, configure detectors. Notice
**no `implementation("...:deviceintelligence:0.1.0")` line** — the plugin auto-adds
the matching runtime AAR for you, locked to the same version as itself.

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("io.ssemaj.deviceintelligence") version "0.1.0"
}

deviceintelligence {
    verbose.set(true)

    // Opt in to VPN detection (DeviceContext.vpnActive). Off by default
    // because it injects ACCESS_NETWORK_STATE into your manifest.
    enableVpnDetection.set(true)

    // Opt in to biometrics-enrollment detection
    // (DeviceContext.biometricsEnrolled). Off by default because it
    // injects USE_BIOMETRIC. Normal-protection, no Play review impact.
    enableBiometricsDetection.set(true)
}
```

Collect at runtime:

```kotlin
val report = DeviceIntelligence.collect(context)        // typed object
val json = DeviceIntelligence.collectJson(context)      // canonical JSON
```

The library auto-initializes via a manifest-merged `ContentProvider`, so `collect`
is safe to call from any thread without explicit setup. The init provider also
kicks off a background pre-warm pass so the first user-visible `collect` returns
from cached state in single-digit ms.

### Library-only mode (advanced)

If you want the runtime AAR without the Gradle plugin's build-time work — for
example, you want to **skip F10 (APK integrity) entirely** and just collect
device intelligence at runtime — drop the plugin and pull the AAR directly:

```kotlin
// settings.gradle.kts: no eachPlugin block needed; just the JitPack repo
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:0.1.0")
}
```

Without the plugin, the F10 fingerprint asset is absent at runtime, so the
APK-integrity detector reports `status: "inconclusive"` with
`inconclusive_reason: "asset_missing"`. Every other detector works unchanged.

You can also keep the plugin's manifest-injection work but skip the auto-applied
AAR (e.g. when the AAR is delivered via a wrapper module the plugin can't see)
by setting `disableAutoRuntimeDependency = true` in the DSL block, or passing
`-Pdeviceintelligence.disableAutoRuntimeDependency=true` on the command line.

### What the Gradle plugin does at build time

Per variant, the plugin:

1. Computes a SHA-256 fingerprint over your APK's entries.
2. Encrypts the fingerprint blob with a per-build XOR key whose chunks are split
   across generated Kotlin classes (a *cost amplifier*, not encryption — it defeats
   `unzip + grep` and naive blob substitution).
3. Injects the encrypted blob as an asset (`assets/io.ssemaj/fingerprint.bin`)
   before re-signing the APK with your `signingConfig` (v1+v2+v3).
4. Generates a small manifest fragment with whatever opt-in permissions you enabled
   (`ACCESS_NETWORK_STATE` for VPN detection, `USE_BIOMETRIC` for biometrics-enrollment
   detection) and wires it into your variant via `addGeneratedManifestFile`.
5. Adds the matching runtime AAR coordinate to your `implementation`
   configuration — same group, same version as the plugin itself, so the
   runtime classes that read the build-time fingerprint are always at the
   exact wire-schema version the plugin emitted them under.

## Output shape

The `device.*` block ships ~60 fields grouped by purpose. Every observability
field is nullable: a single failing accessor (sensor service unavailable,
permission missing, weird OEM fork) only blanks that one field — the surrounding
report is unaffected.

| Group | Fields | What backends use it for |
|---|---|---|
| **Identity** | `manufacturer`, `model`, `sdk_int`, `abi`, `fingerprint` | Always-present basics |
| **Hardware identity** | `brand`, `board`, `hardware`, `product`, `device`, `bootloader_version`, `radio_version`, `build_*`, `supported_abis_all`, `soc_manufacturer` (API 31+), `soc_model` (API 31+) | Cohort by SoC / OEM ROM. Catches every emulator (`hardware = goldfish/ranchu`) and every custom ROM (`build_host` doesn't match the OEM CI farm). |
| **Resources** | `total_ram_mb`, `cpu_cores`, `screen_density_dpi`, `screen_resolution`, `sensor_count`, `boot_count` | Form-factor + emulator heuristics |
| **GPU / EGL** | `gl_es_version`, `egl_implementation` | Strong emulator tell — `swiftshader` / `mesa` give them away. |
| **Locale + timezone** | `default_locale`, `system_locales`, `timezone_id`, `timezone_offset_minutes`, `auto_time_enabled`, `auto_time_zone_enabled` | Geo-cohort without GPS. Backend correlates timezone vs IP geolocation — mismatch is a strong VPN-fraud signal. Manual clock on a "production" device usually means a fraud rig. |
| **Display extras** | `display_refresh_rate_hz`, `display_supported_refresh_rates_hz`, `display_hdr_types` | Modern flagships report 120Hz + HDR10+; emulators stuck at 60Hz with no HDR. |
| **Security posture** | `strongbox_available`, `device_secure`, `biometrics_enrolled`†, `adb_enabled`, `developer_options_enabled` | Bot farms / dev rigs leak here — no lockscreen, ADB on, dev options on. |
| **Battery + thermal** | `battery_present`, `battery_technology`, `battery_health`, `battery_plug_type`, `thermal_status` (API 29+) | Emulators report `Unknown` battery tech. Click farms are always plugged in (correlate `plug_type ≠ none` across many reports per device). |
| **Boot derivation** | `boot_epoch_ms` | Cheap cohort + clock-jump fraud detection. |
| **Network** | `vpn_active`† | Active VPN transport — opt-in via `enableVpnDetection`. |
| **Google ecosystem** | `play_services_availability`, `play_services_version_code`, `play_store_version_code`, `gms_signer_sha256` | Confirms Google ecosystem (or not — MicroG, Huawei, custom ROMs). The signer hash distinguishes real Google-signed GMS from re-signed / spoofed copies. |

† Requires consumer to opt in via the Gradle DSL — see [Permissions](#permissions).

### What a real report looks like

Below is a **representative report** in the exact wire format your backend
will receive — zero findings, every `device.*` and `app.*` field shown, no
fields trimmed. Captured live from a clean Pixel 9 Pro and then lightly
sanitised (locale / timezone / install timestamps / `vpn_active` / `boot_count`
/ APK random suffixes) so this README example doesn't pin to one specific
maintainer's device. The structure, field types, and value vocabularies are
exactly what the SDK emits.

```json
{
  "schema_version": 1,
  "library_version": "0.1.0",
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
    "supported_abis_all": [
      "arm64-v8a"
    ],
    "soc_manufacturer": "Google",
    "soc_model": "Tensor G4",
    "gl_es_version": "3.2",
    "egl_implementation": "mali",
    "default_locale": "en-US",
    "system_locales": [
      "en-US"
    ],
    "timezone_id": "America/Los_Angeles",
    "timezone_offset_minutes": -480,
    "auto_time_enabled": true,
    "auto_time_zone_enabled": true,
    "display_refresh_rate_hz": 120.0,
    "display_supported_refresh_rates_hz": [1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 24.0, 30.0, 40.0, 60.0, 120.0],
    "display_hdr_types": [
      "HDR10",
      "HLG",
      "HDR10_PLUS"
    ],
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
    "signer_cert_sha256": [
      "a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4"
    ],
    "build_variant": "debug",
    "library_plugin_version": "0.1.0",
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
      "attested_signer_cert_sha256": [
        "a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4"
      ],
      "verdict_device_recognition": "MEETS_BASIC_INTEGRITY,MEETS_DEVICE_INTEGRITY,MEETS_STRONG_INTEGRITY",
      "verdict_app_recognition": "RECOGNIZED",
      "verdict_reason": null,
      "verdict_authoritative": false,
      "unavailable_reason": null
    }
  },
  "detectors": [
    {
      "id": "F10.apk_integrity",
      "status": "ok",
      "duration_ms": 841,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F12.emulator_probe",
      "status": "ok",
      "duration_ms": 0,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F13.cloner_probe",
      "status": "ok",
      "duration_ms": 0,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F14.key_attestation",
      "status": "ok",
      "duration_ms": 495,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F15.bootloader_integrity",
      "status": "ok",
      "duration_ms": 243,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F16.runtime_environment",
      "status": "ok",
      "duration_ms": 5525,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "F17.root_indicators",
      "status": "ok",
      "duration_ms": 458,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    }
  ],
  "summary": {
    "total_findings": 0,
    "findings_by_severity": {
      "low": 0,
      "medium": 0,
      "high": 0,
      "critical": 0
    },
    "findings_by_kind": {},
    "detectors_with_findings": [],
    "detectors_inconclusive": [],
    "detectors_errored": []
  }
}
```

> **About this dump.** Captured live from a clean Pixel 9 Pro running
> `samples/minimal` (Android 16, Tensor G4) and then lightly sanitised
> for this README. The structure, field names, types, value vocabularies,
> and ordering are **byte-exact** to what the SDK emits — nothing was
> reshaped or reordered. What *was* changed: `default_locale` /
> `system_locales` / `timezone_id` / `timezone_offset_minutes` swapped
> to a generic `en-US` / `America/Los_Angeles`, `vpn_active` / `adb_enabled`
> / `developer_options_enabled` flipped to `false` (so this isn't pinned
> to one maintainer's dev environment), `boot_count` rounded, the four
> install / boot / collection epoch timestamps replaced with plausible
> fixed values, and the random suffixes in `apk_path` shortened to `...`.
> Everything else — including the StrongBox-backed attestation block,
> the Tensor G4 SoC identity, the Pixel 9 Pro Mali GPU + 120 Hz panel +
> 11-rate refresh ladder, and the GMS signer SHA — is the unmodified
> real value. For what a *tripped* finding looks like, see the
> [Bootloader integrity](#bootloader-integrity-f15) and
> [Root indicators](#root-indicators-f17) sections below.

The "no news is good news" pattern is uniform across detectors: a clean device
emits a report with empty `findings[]` arrays everywhere and `summary.total_findings: 0`.
You can alert on `total_findings > 0` server-side without parsing each detector
individually.

## Stable contract

For each `Finding` these fields are **stable** (safe to key on, alert on, group by
from a backend) across releases that share the same `schema_version`:

- `kind` — stable identifier
- `severity` — `low` / `medium` / `high` / `critical`. The library *suggests* a
  severity per finding; backends are free to override per their own policy.
- `subject` — what was checked (package name, APK entry, region label)
- `message` — deterministic human-readable one-liner

`details` is **opaque diagnostic data**. Useful for forensics. Its keys may change
between releases without a `schema_version` bump — don't key on them server-side.

A wire-format-breaking change bumps `schema_version`. The current version is `1`.

### `status` vs `findings` — read this once

A common gotcha: a detector can report `status: "ok"` *and* still have a non-empty
`findings` array. That is **not** a bug. The two fields answer different questions:

- `status` answers **"did the detector run?"**
  - `ok` — detector executed cleanly
  - `inconclusive` — detector tried but couldn't reach a verdict (missing native
    lib, unreadable `/proc` file, format skew on a weird OEM fork) →
    `inconclusive_reason` explains
  - `error` — detector threw → `error_message` has the trace
- `findings[]` answers **"what did it see?"** Each entry is one signal it picked up.

So a rooted device looks like this (truncated):

```json
{
  "id": "F17.root_indicators",
  "status": "ok",
  "findings": [
    { "kind": "root_manager_app_installed", "severity": "high", ... }
  ]
}
```

`status: "ok"` means F17 ran successfully. The `findings` entry means it found a
root manager app installed. Both facts are independently true.

**Why split it?** A backend has to distinguish three different "no findings"
cases that look identical if you collapse them: clean device (`status=ok,
findings=[]`), broken on this device (`status=inconclusive`), and crashed on this
device (`status=error`). Using `status` to mean "no findings" would silently let
broken detectors on weird ROMs count toward your clean-rate metric.

The roll-up that *does* answer "did anything trip?" lives in `summary`:

```json
"summary": {
  "total_findings": 3,
  "findings_by_severity": { "low": 0, "medium": 1, "high": 2, "critical": 0 },
  "detectors_with_findings": ["F14.key_attestation", "F15.bootloader_integrity", "F17.root_indicators"]
}
```

`detectors_with_findings` is the list to drive a "device looks tampered"
decision off — not `status`.

## Detector deep dives

### Hardware key attestation (F14) and `app.attestation`

`F14.key_attestation` is the only detector that talks to the device's TEE
/ StrongBox directly. It requests an attested EC keypair and parses the
`KeyDescription` extension Google's KeyMint signs into the leaf cert
(`OID 1.3.6.1.4.1.11129.2.1.17`).

Its output lives in **two places**, on purpose:

- **`app.attestation`** (top of the report) — the **always-shipped
  evidence + advisory verdict**. Present on every report (when the
  device supports hardware attestation), even on perfectly clean
  devices. The JSON ships a compact actionable subset: a SHA-256
  correlation key for the chain (`chain_sha256`), the security level
  the chain came back at (`attestation_security_level` /
  `keymaster_security_level` — `StrongBox` / `TrustedEnvironment` /
  `Software` — plus a derived `software_backed` boolean that's `true`
  iff *either* level is `Software`, useful for one-key cohort filters
  on backends that don't want to OR two strings), Verified Boot state,
  `device_locked`, OS patch level, attested package + signer, and the
  Play-Integrity-shaped advisory (`verdict_device_recognition` /
  `verdict_app_recognition` / `verdict_reason`). A backend that needs
  an authoritative verdict
  MUST re-verify the **chain bytes** against Google's
  hardware-attestation root and the
  [attestation revocation list](https://android.googleapis.com/attestation/status)
  server-side. The library does not do this on-device by design — an
  attacker who controls userland could patch the on-device verifier
  out. `verdict_authoritative` is always `false`: the local verdict is
  for in-app UX gating; trust the re-verified chain for security
  decisions.

  > **Where are the chain bytes?** To keep the JSON wire format
  > compact and human-readable for open-source consumers, the raw
  > base64 chain (~5KB) and a handful of diagnostic fields
  > (`attestation_challenge_b64`, `attested_application_id_sha256`,
  > `verified_boot_key_sha256`, `keymaster_version`, `os_version`,
  > `vendor_patch_level`, `boot_patch_level`) are **not** in the JSON
  > by default. They live on the typed `AttestationReport` Kotlin
  > object — backend uploaders that need to ship the bytes for
  > authoritative re-verification read them off the typed report
  > directly:
  >
  > ```kotlin
  > val report = DeviceIntelligence.collect(context)
  > val chainB64: String? = report.app.attestation?.chainB64
  > val chainSha: String? = report.app.attestation?.chainSha256
  > // Upload chainB64 alongside the JSON; chainSha256 lets the backend
  > // dedup and correlate across reports without parsing the chain.
  > ```

- **F14 findings** (`tee_integrity_verdict`) — emitted **only when the
  local verdict is degraded** (severity > LOW). On a clean device F14
  contributes zero findings, matching the rest of the library's
  "no news is good news" pattern. The verdict's wire spellings mirror
  Play Integrity (`MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`,
  `MEETS_STRONG_INTEGRITY`) so backends already wired up to Play
  Integrity can consume them without a remapping table.

Hardware key attestation requires Android 9 (API 28), which is
also the library's `minSdk` floor — so on any device that runs the
SDK at all, the surface is available. Where keygen still fails
(rare; stripped AOSP, no-TEE emulator), `app.attestation` is
non-null with `unavailable_reason` populated and the parsed fields
all `null` — backends always see the same shape. Cold-start cost
(~80–500ms TEE / ~0.5–4s StrongBox) is absorbed by the
manifest-merged init provider on a background thread, so user-facing
`collect()` reads the cached chain in single-digit ms.

### Bootloader integrity (F15)

F14 reports what the TEE *claims*. On a device with
[Tricky Store](https://github.com/5ec1cff/TrickyStore) / LSPosed installed,
the AndroidKeyStore surface itself is hooked: the attacker captures a clean
attestation chain on a known-good boot session and replays it on every
subsequent keygen call. F14 sees a well-formed chain, parses it, and
dutifully reports `device_locked = true` even though `getprop ro.boot.flash.locked`
shows the bootloader as unlocked.

`F15.bootloader_integrity` raises the cost of that bypass with orthogonal
cross-checks. It runs a **second** attestation under a fresh alias + nonce
and compares it to F14's. On a clean device it emits **zero findings** and
costs one extra TEE keygen (~80–500ms TEE / ~0.5–4s StrongBox), absorbed by
the same background pre-warm that runs F14. On a device where any of the
checks trip, it emits one finding per tripped check with a stable
`subreason` code in `details`:

| Finding kind                            | Subreason                            | Severity | Triggered when                                                                                                                              |
| --------------------------------------- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `bootloader_integrity_anomaly`          | `chain_empty`                        | high     | F14's chain has no certs                                                                                                                    |
| `bootloader_integrity_anomaly`          | `chain_too_short`                    | high     | F14's chain has fewer than 2 certs (real attestation chains have leaf + ≥1 issuer)                                                          |
| `bootloader_integrity_anomaly`          | `chain_signature_invalid`            | high     | A cert in the chain doesn't verify against its issuer's public key                                                                          |
| `bootloader_integrity_anomaly`          | `chain_root_not_self_signed`         | high     | The root cert doesn't self-sign                                                                                                             |
| `bootloader_integrity_anomaly`          | `validity_child_predates_parent`     | high     | An intermediate cert's `notBefore` precedes its issuer's (leaf is skipped — KeyMint uses fixed `1970..2048` defaults)                       |
| `bootloader_integrity_anomaly`          | `validity_child_outlasts_parent`     | high     | An intermediate cert's `notAfter` outlasts its issuer's                                                                                     |
| `bootloader_integrity_anomaly`          | `challenge_not_echoed`               | high     | The leaf doesn't embed the nonce we asked the TEE to attest                                                                                 |
| `bootloader_integrity_anomaly`          | `freshness_pubkey_identical`         | high     | Two consecutive keygens (under different aliases) produced leaf certs with the same SubjectPublicKey                                        |
| `bootloader_integrity_anomaly`          | `freshness_challenge_identical`      | high     | Two consecutive keygens (with different nonces) produced leaf certs that echo the same attestation challenge                                |
| `bootloader_integrity_anomaly`          | `leaf_pubkey_mismatch`               | high     | The leaf cert's SubjectPublicKey doesn't match the public key the AndroidKeyStore actually holds for our alias                              |
| `bootloader_integrity_anomaly`          | `leaf_pubkey_unreadable`             | medium   | Defensive: leaf's pubkey couldn't be decoded for comparison                                                                                 |
| `bootloader_strongbox_unavailable`      | `strongbox_unexpectedly_unavailable` | medium   | Device advertises StrongBox capability — either via `PackageManager.FEATURE_STRONGBOX_KEYSTORE` or by being on the Pixel-3+ denylist — but the attestation came back at TEE / SOFTWARE security level |

> **Why no leaf-validity / leaf-serial / leaf-age checks?** Real Android
> KeyMint sets the attestation leaf cert's `notBefore = 1970-01-01`,
> `notAfter = 2048-01-01`, and `serialNumber = 1` for *every* attested
> key — these fields carry no per-keygen meaning, so checks against them
> would false-positive on every clean device. F15 instead derives
> freshness signals from data the TEE *does* sign meaningfully: the
> embedded attestation challenge and the leaf SubjectPublicKey.

A tripped F15 finding looks like this in the JSON output:

```json
{
  "id": "F15.bootloader_integrity",
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

Same authority caveat as F14: `verdict_authoritative` is always `"false"`.
F15 raises the cost of a bypass and surfaces high-signal red flags, but
the authoritative verdict still comes from a backend that re-verifies F14's
chain (`report.app.attestation.chainB64`, accessed off the typed report —
not in the JSON wire format by default) against Google's pinned root +
revocation list and correlates signals across the fleet over time.

Returns `status: "inconclusive"` with reason `f14_unavailable` if
F14 hasn't cached a result yet, or with the same failure-reason
vocabulary as F14 (`attestation_not_supported`, `keystore_error`,
`keystore_unavailable`) if F15's own keygen fails.

### Runtime environment (F16)

`F16.runtime_environment` watches for tampering signals that show up
inside our own process the moment something attaches to or injects
into us. Four orthogonal channels, all powered by a single
`/proc/self/maps` read and a single `/proc/self/status` read; result
is cached for the process lifetime:

| Finding kind                 | Severity | Triggered when                                                                                                                              |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `debugger_attached`          | high     | `Debug.isDebuggerConnected()` is true OR `/proc/self/status` reports a non-zero `TracerPid` (gdb / lldb / `frida-trace` / strace attached)  |
| `ro_debuggable_mismatch`     | high     | The app's own `FLAG_DEBUGGABLE` disagrees with the system's `ro.debuggable` property (classic repackaging tell)                             |
| `hook_framework_present`     | high     | A library matching a known hooking-framework signature is mapped into the process (Frida, Substrate, Xposed, LSPosed, Riru, Zygisk, Taichi) |
| `rwx_memory_mapping`         | high     | A read-write-executable page mapping exists in the process (the Android loader never produces `rwxp` / `rwxs` regions; JIT trampoline tell) |

Hook-framework matches emit one finding per distinct framework
(canonical name in `details.framework`), so backends can triage
each one independently. RWX mappings emit a single finding with up
to 8 region descriptors in `details.region_*`; if there are more,
the last entry is a `... +N more` overflow marker.

Costs ~2-5 ms total on a clean device (one `/proc` read, one short
status parse, plus the maps scan). Always returns `status: "ok"` —
the only failure mode is the native bridge being unavailable, in
which case the maps-dependent checks silently degrade to "no signal"
rather than reporting the detector as inconclusive.

### Root indicators (F17)

`F17.root_indicators` covers the filesystem-, shell-, and
installed-app-level root signals that pair with F14's TEE-attested
`verified_boot_state`. None of these are individually authoritative
— every one of them can be hidden by a sufficiently determined root
tool (Magisk's DenyList, Zygisk modules, etc.) — so this detector
is best thought of as the "low-hanging fruit" layer. A device that
trips F17 is a device whose owner did not even bother to hide the
root.

| Finding kind                 | Severity | Triggered when                                                                                                                              |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `su_binary_present`          | high     | An `su` binary exists at one of the canonical hardcoded paths or in any directory on `$PATH` (one finding per matching path)                |
| `magisk_artifact_present`    | high     | A Magisk-shipped file/dir exists OR `/proc/mounts` has a `magisk`-named entry (one finding per matching artifact, descriptor in `details.artifact`) |
| `test_keys_build`            | medium   | `ro.build.tags` reports `test-keys` (custom ROM, eng build, or hand-edited build.prop)                                                      |
| `which_su_succeeded`         | high     | `Runtime.exec("which su")` resolved to a binary not on the hardcoded path list (only run when no other `su` hits, ~30-80ms cost)            |
| `root_manager_app_installed` | medium   | A known root-manager / Xposed-manager app is installed (one finding per matched package, name in `details.package_name`)                    |

> **Permission notice — `QUERY_ALL_PACKAGES`.** Package visibility
> for the root-manager check is provided by
> `android.permission.QUERY_ALL_PACKAGES`, declared in the library
> manifest. This permission is merged into every consuming app and
> is treated as a [restricted permission by Google Play](https://support.google.com/googleplay/android-developer/answer/10158779);
> consumers shipping to Play must justify it under one of the
> permitted use cases ("anti-malware / device security" is the
> relevant category for DeviceIntelligence-driven integrity
> telemetry). Consumers who cannot justify it can strip it via
> manifest-merger:
>
> ```xml
> <uses-permission
>     android:name="android.permission.QUERY_ALL_PACKAGES"
>     tools:node="remove" />
> ```
>
> F17 then silently degrades to channels 1-4 (`su` binary,
> Magisk artifacts, `test-keys`, `which su`) — only the
> `root_manager_app_installed` channel is affected.

Same defense-in-depth principle as the rest of the library: if F17
trips, pair it with the TEE-attested `verified_boot_state` from
`app.attestation` for an authoritative cross-check. If F17 says
"clean" but `verified_boot_state` is `Unverified`, the device is
likely running a root tool that hides from filesystem-level checks.

## Permissions

DeviceIntelligence ships with the absolute minimum permission set in the library
AAR, and every additional permission is opt-in through the Gradle plugin DSL so
consumers can decide per-app.

| Permission                       | Where it lives                                | Required by                                              | Opt-in mechanism                                  |
|----------------------------------|-----------------------------------------------|----------------------------------------------------------|---------------------------------------------------|
| `QUERY_ALL_PACKAGES`             | Library manifest (always merged in)           | F17 `root_manager_app_installed` channel                 | Strip via `tools:node="remove"`                   |
| `ACCESS_NETWORK_STATE`           | Generated manifest fragment (opt-in)          | `DeviceContext.vpnActive`                                | `enableVpnDetection.set(true)` in Gradle          |
| `USE_BIOMETRIC`                  | Generated manifest fragment (opt-in)          | `DeviceContext.biometricsEnrolled`                       | `enableBiometricsDetection.set(true)` in Gradle   |

When you opt out of a permission, the affected field reports `null` rather than
`false` so backends can distinguish "no signal" from "negative signal".

`QUERY_ALL_PACKAGES` is the one to think hardest about: it's a
[Google-Play-restricted permission](https://support.google.com/googleplay/android-developer/answer/10158779)
and your Play Console submission needs to justify it under "anti-malware / device
security". If you can't or don't want to, strip it as shown above and F17 silently
degrades; the rest of the library is unaffected.

## Performance, threading, caching

| Concern              | Behavior                                                                                                                                                                                                                                               |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cold-start cost      | A manifest-merged `ContentProvider` triggers `System.loadLibrary("dicore")` and a background pre-warm pass before `Application.onCreate` runs. The first user-visible `collect()` sees cached state and returns in single-digit ms.                    |
| Hot-path `collect()` | ~tens of ms on a warm process (one APK ZIP walk dominates F10; F14/F15 hit cached attestation results; F16/F17 hit cached `/proc` parses).                                                                                                            |
| Threading            | `collect()` is safe to call from any thread. For production, call it off the main thread anyway — the *first* call after process start may not be fully warm yet.                                                                                      |
| Caching              | Each detector caches what it sensibly can for the process lifetime (attestation chain, `/proc/self/maps` parse, `/proc/mounts` parse, root-manager lookup). The library deliberately does NOT cache the full report — the consumer is the right owner of "how often". |
| Native lib size      | `libdicore.so` is built per ABI (`arm64-v8a` + `x86_64` only), with `-fvisibility=hidden`, `-ffunction-sections`, `--gc-sections`. Currently ~230-250 KB stripped per ABI for the release variant; debug builds are larger because they retain the unwind tables.                                                                                |

## The sample app

`samples/minimal/` is a single-Activity app that re-runs `DeviceIntelligence.collect`
on demand and renders the resulting report as a stack of cards (Hero, Actions,
Device, App, Findings, Detectors, JSON). It's built with programmatic Kotlin UI
(no XML, no Compose, no AndroidX dependencies) so the whole app — including the
custom dark/light palette, the wrapping chip layout, and the JSON viewer — is in
two files: `MainActivity.kt` and `Ui.kt`.

```sh
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

The `Re-collect` button re-runs every detector and re-renders. The `Copy JSON`
button puts the canonical JSON on the clipboard — exactly what your backend
would receive, byte for byte.

## Building from source

```sh
# Tests + sample APK
./gradlew :deviceintelligence:test :samples:minimal:assembleDebug

# Library AAR (release variant)
./gradlew :deviceintelligence:assembleRelease
# → deviceintelligence/build/outputs/aar/deviceintelligence-release.aar

# Just the Gradle plugin (lives in an included build at the root settings)
./gradlew -p deviceintelligence-gradle build

# Publish both halves to the local Maven repo for smoke-testing against an
# external consumer (mirrors what JitPack does on a tag push):
./gradlew :deviceintelligence:publishToMavenLocal
./gradlew -p deviceintelligence-gradle publishToMavenLocal
# → ~/.m2/repository/com/github/iamjosephmj/DeviceIntelligence/...
```

Requirements:

- JDK 17 (Android Studio's bundled JBR works fine — set `JAVA_HOME` to it if your
  system Java is older).
- Android SDK with `platforms;android-36` and `build-tools;36.0.0`.
- Android NDK `27.0.12077973` (CMake builds the `dicore` native lib).

For published consumption use [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence)
— see [Quickstart](#quickstart). The Maven Central path is on the
[Roadmap](#roadmap).

## Project layout

```
deviceintelligence/         ← runtime AAR (Kotlin + JNI native lib libdicore.so)
deviceintelligence-gradle/  ← build-time plugin (lives in an included build)
samples/minimal/            ← sample app: programmatic UI that renders the JSON
tools/                      ← APK build / instrumentation helper scripts
dist/                       ← demo APKs the build scripts produce
jitpack.yml                 ← JitPack build config (SDK + NDK install + publish)
```

The runtime SDK has roughly two layers:

- **Kotlin orchestration** (`deviceintelligence/src/main/kotlin/`) — public API
  surface, the `Detector` plugin contract, the `TelemetryCollector` orchestrator,
  per-detector implementations, hand-rolled JSON serializer (no Moshi / Gson
  dependency).
- **Native probes** (`deviceintelligence/src/main/cpp/`) — minimal C++17 code
  doing the things the JVM either can't do (raw syscalls for the cloner probe,
  arm64 MRS / x86_64 CPUID for the emulator probe) or can't do efficiently (APK
  ZIP parse, signing-block parse, `/proc/self/maps` read).

## Roadmap

This is a pre-1.0 library. The detector set and wire format are stable; what's
not yet there:

- **JitPack distribution — shipped.** Both halves (runtime AAR + Gradle plugin)
  publish on every git tag; coordinates documented in [Quickstart](#quickstart).
- **Maven Central artifact** — JitPack covers the immediate "I want a published
  artifact" need; Maven Central is the next step (signed POMs + Sonatype
  validation) once the wire schema is locked at 1.0. Track via
  [issues](https://github.com/iamjosephmj/DeviceIntelligence/issues).
- **Backend reference verifier** — sample server-side code that validates the
  attestation `chainB64` against Google's hardware root + revocation list, and
  shows how to correlate F14/F15/F16/F17 findings into a single decision.
- **Deeper hooking-detection signals (in progress)** — F16 today is
  *name-based*: it scans `/proc/self/maps` for known hooking-framework
  library signatures (Frida / Substrate / Xposed / LSPosed / Riru / Zygisk
  / Taichi) and reports `hook_framework_present`. That catches the loaded
  library, but not the *act* of hooking itself, which means a renamed or
  in-memory-only agent currently slips through. We're building the next
  layer: **integrity-style hook detection** — PLT / GOT entry inspection
  for resolved libc / libart symbols, inline-trampoline detection at the
  prologue of hot ART / JNI entry points, JNI function-table tampering
  checks (`JNIEnv->GetMethodID` and friends rewritten by an attacker),
  and `dlopen` / `linker` audit-trail diffing. Targeted as additional
  finding kinds inside the existing `F16.runtime_environment` detector
  so backends don't have to track a new id; design notes and progress
  will land in a tracking issue once the API surface is firm.
- **More detector suggestions welcome** — see [Contributing](#contributing).

The public Kotlin surface (`DeviceIntelligence.collect`, `DeviceIntelligence.collectJson`,
plus the data classes in `Telemetry.kt`) is intentionally tiny and won't grow
without a `schema_version` bump.

## Contributing

Issues, PRs, and ideas for new detectors are all welcome. A few principles to
keep in mind if you're proposing changes:

1. **Telemetry, not RASP.** Detectors observe; they do not decide. Anything
   that reaches into `System.exit`, `Process.killProcess`, "kill the network
   stack", "wipe encrypted data", or "lock the user out" territory belongs in
   the consumer's policy layer (their backend, or their own in-app code that
   reads our JSON). Not here. PRs that add on-device enforcement will be
   declined on principle.
2. **Document the bypass model.** Every detector's deep-dive section explains
   *exactly* how that signal can be defeated. Be honest. A "perfect" detector
   would not survive the next minor Android release; what you want is a layer
   that's *expensive enough to bypass* relative to its cost to maintain.
3. **No throwing.** Detectors must wrap their failures and return a
   `DetectorStatus.ERROR` report. A detector that throws breaks the entire
   `collect()` call for the consumer.
4. **Wire format = stable contract.** Adding fields to `Finding.details` is fine
   without a schema bump. Renaming or removing anything stable (`kind`,
   `severity`, `subject`, `message`, the field names under `device` / `app` /
   `summary`) is a breaking change and requires bumping `schema_version`.
5. **Keep it small.** The native lib is currently ~230-250 KB stripped per ABI
   (release). New native code should justify its bytes. The pure-Kotlin
   orchestrator has zero third-party runtime dependencies — let's keep it that way.

For non-trivial changes, please open an issue first so we can talk through the
design before you spend time on a PR.

### Reporting a security issue

If you think you've found a security-relevant bug (a way to make a detector miss
something it should catch, a way to crash the host app, a way to exfiltrate data
the library shouldn't be exposing), please **do not file a public issue**. Email
the maintainer at the address listed on the GitHub profile, or open a private
[security advisory](https://github.com/iamjosephmj/DeviceIntelligence/security/advisories)
on the repo.

## Prior art and acknowledgments

DeviceIntelligence stands on the shoulders of a lot of public Android security
research. Specific things we lean on or learn from:

- [Google's Android Key Attestation sample](https://github.com/google/android-key-attestation)
  — reference for parsing the `KeyDescription` extension.
- [AOSP's Verified Boot documentation](https://source.android.com/docs/security/features/verifiedboot)
  — semantics of `verified_boot_state` and the bootloader-lock signals F14
  surfaces.
- [Tricky Store](https://github.com/5ec1cff/TrickyStore) and the broader LSPosed
  / Magisk research community — the bypass model F15 is built around.
- [RootBeer](https://github.com/scottyab/rootbeer) and [SafetyNetSamples](https://github.com/googlesamples/android-play-safetynet)
  — prior art for the F17 signal vocabulary.
- [Frida](https://frida.re/) and [LSPosed](https://github.com/LSPosed/LSPosed)
  themselves — the canonical hooking-framework signatures F16 watches for.

If your project is a direct inspiration and isn't credited here, please open a
PR — happy to add it.

## License

```
Copyright 2026 Joseph James (iamjosephmj)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

See the [`LICENSE`](LICENSE) file for the full text.
