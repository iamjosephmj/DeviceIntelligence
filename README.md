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
  <img alt="Schema" src="https://img.shields.io/badge/wire_schema-v2-orange.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-pre--1.0-yellow.svg">
</p>

---

## Install

Distributed via [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence).
**One plugin, one version** — for a **normal external app** the plugin adds the
matching runtime AAR to `implementation` for you, so you do **not** declare a
second `implementation("…:deviceintelligence:…")` line.

> **When you *do* add `implementation` yourself:** only if your root build also
> `include`s the upstream `:deviceintelligence` project (monorepo or vendor fork).
> In that case the plugin would otherwise wire `project(":deviceintelligence")`
> for fast local iteration. To use the **published** JitPack AAR instead — same
> as a real consumer — set `deviceintelligence { disableAutoRuntimeDependency.set(true) }`
> **and** add  
> `implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:<plugin version>")`  
> (same version string as the plugin, e.g. `0.2.0`). This repository’s
> [`samples/minimal/build.gradle.kts`](samples/minimal/build.gradle.kts) uses
> that pattern (`libs.deviceintelligence` in the version catalog). Full rationale:
> [Quickstart → Add it to your own app](#add-it-to-your-own-app).

**1. `settings.gradle.kts`** — declare the JitPack repo and map the plugin id to its JitPack-published module ([why](#quickstart)):

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

**2. `app/build.gradle.kts`** — apply the plugin (version = JitPack tag, e.g.
`0.2.0`). For a standalone app, **nothing else** — the plugin adds the runtime
AAR for you.

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("io.ssemaj.deviceintelligence") version "0.2.0"
}

// Standalone app (default): no `dependencies { implementation("...:deviceintelligence:0.2.0") }`
// line. The plugin auto-wires the matching runtime AAR.
```

<details>
<summary><strong>Monorepo / vendor fork</strong> — your build also includes <code>:deviceintelligence</code> as a project (click to expand)</summary>

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("io.ssemaj.deviceintelligence") version "0.2.0"
}

deviceintelligence {
    // Stop the plugin from substituting project(":deviceintelligence").
    disableAutoRuntimeDependency.set(true)
}

dependencies {
    // Use the published AAR. MUST match the plugin version above.
    implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:0.2.0")
}
```

This is exactly what [`samples/minimal/build.gradle.kts`](samples/minimal/build.gradle.kts)
does (via `libs.deviceintelligence` in the version catalog), so the in-repo sample
matches what an external JitPack consumer resolves. See
[Quickstart → Add it to your own app](#add-it-to-your-own-app) for the rationale.

</details>

**3. Collect at runtime** — anywhere in your app, off the main thread:

```kotlin
val report = DeviceIntelligence.collect(context)        // typed object
val json = DeviceIntelligence.collectJson(context)      // canonical JSON
```

The library auto-initializes via a manifest-merged `ContentProvider` and pre-warms
in the background, so the first user-visible `collect` returns from cached state
in single-digit ms.

For configuration options (VPN detection, biometrics-enrollment detection,
opt-out flags), the library-only mode (skip the plugin), and the full deep dive
on what the Gradle plugin does at build time, see [Quickstart](#quickstart) and
[Permissions](#permissions) below.

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

- [Install](#install)
- [Why DeviceIntelligence?](#why-deviceintelligence)
  - [Why telemetry, not RASP?](#why-telemetry-not-rasp)
- [What it collects](#what-it-collects)
- [Quickstart](#quickstart)
- [Output shape](#output-shape)
- [Stable contract](#stable-contract)
  - [`status` vs `findings` — read this once](#status-vs-findings--read-this-once)
- [Detector reference](#detector-reference) — full per-detector deep dive lives in [`docs/DETECTORS.md`](docs/DETECTORS.md)
- [Permissions](#permissions)
- [Performance, threading, caching](#performance-threading-caching)
- [The sample app](#the-sample-app)
- [Building from source](#building-from-source)
- [Project layout](#project-layout)
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
| Stable, versioned wire format | Yes | Vendor-specific | No | **Yes (`schema_version: 2`)** |
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
| APK integrity         | `integrity.apk`               | APK bytes vs. the build-time fingerprint baked by the Gradle plugin                              |
| Bootloader integrity  | `integrity.bootloader`        | Cross-checks `attestation.key`'s chain against a second attestation to surface TEE spoofing / cached chains |
| ART integrity         | `integrity.art`               | In-process ART tampering across five orthogonal vectors: ArtMethod entry-point rewrites (Xposed-family + Frida-attach detection), JNIEnv function-table tampering (Frida-Java JNI hijacks), inline trampolines on ART hot-paths (Frida `Interceptor.attach`), `entry_point_from_jni_` overwrites (Pine / Dobby / Frida-Java native-method bridges), and `ACC_NATIVE` bit flips (Frida-Java `cls.method.implementation = ...`) |
| Key attestation       | `attestation.key`             | TEE / StrongBox attestation: Verified Boot state, bootloader lock, OS patch level                |
| Runtime environment   | `runtime.environment`         | In-process tampering: debugger / native tracer attached, `ro.debuggable` mismatch, hooking framework loaded (Frida / Xposed / LSPosed / Substrate / Riru / Zygisk / Taichi), RWX memory mappings |
| Root indicators       | `runtime.root`                | `su` binary on disk (PATH walk + hardcoded paths), Magisk artifacts (filesystem + `/proc/mounts`), `ro.build.tags = test-keys`, `which su` fallthrough, known root-manager apps installed |
| Emulator probe        | `runtime.emulator`            | CPU-instruction-level signals (arm64 MRS / x86\_64 CPUID hypervisor bit)                         |
| App cloner            | `runtime.cloner`              | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches                            |

The detector ID is a `<category>.<scope>` pair — `integrity.*` /
`attestation.*` / `runtime.*`. The full reference for every
detector (threat model, finding kinds, sample tripped JSON,
costs, caveats) lives in [`docs/DETECTORS.md`](docs/DETECTORS.md).

Every detector is independent. Adding a new one is a single line
in `TelemetryCollector` and a single class implementing the
internal `Detector` interface — no public-API changes, no
JSON-serializer changes, no policy changes.

## Quickstart

> Distributed via [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence).
> One plugin, one version. For a normal external app the plugin auto-applies the
> matching runtime AAR, so there's no second `implementation(...)` line to keep
> in sync. Monorepos that ship `:deviceintelligence` in the same Gradle build are
> the exception — see the callout under [Add it to your own app](#add-it-to-your-own-app).

### Run the sample app in 30 seconds

```sh
git clone https://github.com/iamjosephmj/DeviceIntelligence.git
cd DeviceIntelligence
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

The sample resolves the Gradle plugin and runtime AAR **`0.2.0` from JitPack**
(same coordinates as [Install](#install)); the first `./gradlew` run needs
network access to fetch them. Because the root build still includes the in-tree
`:deviceintelligence` module for library tests, the sample sets
`disableAutoRuntimeDependency` and declares **`implementation(libs.deviceintelligence)`**
explicitly — see [Add it to your own app](#add-it-to-your-own-app) for why that
pair is needed (normal external apps skip both and rely on the plugin alone).

You'll see a card-based viewer that re-runs every detector on demand and lets you
copy the canonical JSON to your clipboard. On a clean device, every detector
reports `status: "ok"` with `findings: []`.

### Add it to your own app

Replace `0.2.0` below with the latest tag on
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
**no `implementation("...:deviceintelligence:0.2.0")` line** — the plugin auto-adds
the matching runtime AAR for you, locked to the same version as itself.

> **Same Gradle build as `:deviceintelligence`?** If your root `settings.gradle.kts`
> also `include`s this library as a project (typical **monorepo** or vendor fork),
> the plugin detects that module and wires **`implementation(project(":deviceintelligence"))`**
> instead of the JitPack coordinate so local Kotlin / native changes are picked up
> without publishing. To force the **published** AAR anyway — what
> [`samples/minimal/build.gradle.kts`](samples/minimal/build.gradle.kts) does so
> the sample matches a real consumer — set
> `deviceintelligence { disableAutoRuntimeDependency.set(true) }` **and** add the
> runtime dependency yourself, with the **same version** as the plugin (this repo
> uses the version catalog: `implementation(libs.deviceintelligence)` next to
> `alias(libs.plugins.deviceintelligence)`).

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("io.ssemaj.deviceintelligence") version "0.2.0"
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
example, you want to **skip `integrity.apk` entirely** and just collect
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
    implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:0.2.0")
}
```

Without the plugin, the `integrity.apk` fingerprint asset is absent at runtime,
so the APK-integrity detector reports `status: "inconclusive"` with
`inconclusive_reason: "asset_missing"`. Every other detector works unchanged.

You can also keep the plugin's manifest-injection work but skip the auto-applied
AAR (e.g. when the AAR is delivered via a wrapper module the plugin can't see,
or when you need the published coordinate while `:deviceintelligence` still exists
in the same composite — see the callout above) by setting
`disableAutoRuntimeDependency = true` in the DSL block, or passing
`-Pdeviceintelligence.disableAutoRuntimeDependency=true` on the command line.
In that mode the plugin **does not** add any runtime dependency; you **must**
supply `implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:<version>")`
(or your catalog alias) yourself, locked to the same version as the plugin.

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
  "schema_version": 2,
  "library_version": "0.2.0",
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
    "library_plugin_version": "0.2.0",
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
      "id": "integrity.apk",
      "status": "ok",
      "duration_ms": 841,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "integrity.bootloader",
      "status": "ok",
      "duration_ms": 243,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "integrity.art",
      "status": "ok",
      "duration_ms": 4,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "attestation.key",
      "status": "ok",
      "duration_ms": 495,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "runtime.environment",
      "status": "ok",
      "duration_ms": 5525,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "runtime.root",
      "status": "ok",
      "duration_ms": 458,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "runtime.emulator",
      "status": "ok",
      "duration_ms": 0,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": []
    },
    {
      "id": "runtime.cloner",
      "status": "ok",
      "duration_ms": 0,
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
> real value. For what a *tripped* finding looks like for any
> detector, see [`docs/DETECTORS.md`](docs/DETECTORS.md).

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

A wire-format-breaking change bumps `schema_version`. The current version is `2`.

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
  "id": "runtime.root",
  "status": "ok",
  "findings": [
    { "kind": "root_manager_app_installed", "severity": "high", ... }
  ]
}
```

`status: "ok"` means `runtime.root` ran successfully. The `findings` entry
means it found a root manager app installed. Both facts are independently true.

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
  "detectors_with_findings": ["attestation.key", "integrity.bootloader", "runtime.root"]
}
```

`detectors_with_findings` is the list to drive a "device looks tampered"
decision off — not `status`.

## Detector reference

The full per-detector reference — purpose, threat model, finding
kinds, sample tripped JSON, costs, caveats — lives in
[**`docs/DETECTORS.md`**](docs/DETECTORS.md). One section per
detector, in the order they appear in the report:

- [`integrity.apk`](docs/DETECTORS.md#integrityapk) — APK bytes
  vs. the build-time fingerprint baked by the Gradle plugin.
- [`integrity.bootloader`](docs/DETECTORS.md#integritybootloader)
  — cross-checks `attestation.key`'s chain to surface TEE
  spoofing / cached chains.
- [`integrity.art`](docs/DETECTORS.md#integrityart) — in-process
  ART tampering across five orthogonal vectors. The 5-vector deep
  dive (Vector A entry-point rewrites / Vector C JNIEnv table
  hijacks / Vector D inline trampolines / Vector E
  `entry_point_from_jni_` overwrites / Vector F `ACC_NATIVE`
  flips) and the canonical Frida-attach signature live here.
- [`attestation.key`](docs/DETECTORS.md#attestationkey) — TEE /
  StrongBox attestation: Verified Boot, bootloader lock, OS patch
  level. Always-shipped `app.attestation` evidence + advisory
  verdict.
- [`runtime.environment`](docs/DETECTORS.md#runtimeenvironment) —
  debugger / hooker libs / RWX trampoline pages /
  `ro.debuggable` mismatch (the Zygisk fingerprint).
- [`runtime.root`](docs/DETECTORS.md#runtimeroot) — `su` binary,
  Magisk artifacts, `test-keys`, root-manager apps. Includes the
  `QUERY_ALL_PACKAGES` permission notice.
- [`runtime.emulator`](docs/DETECTORS.md#runtimeemulator) —
  CPU-instruction-level signals (arm64 MRS / x86\_64 CPUID
  hypervisor bit).
- [`runtime.cloner`](docs/DETECTORS.md#runtimecloner) — foreign
  APK mappings, mount-namespace inconsistencies, UID mismatches.

The two cross-cutting facts worth keeping in mind here, with
fuller treatment in `docs/DETECTORS.md`:

1.  **`attestation.key`'s chain is the single authoritative
    signal in the whole report**, but only after a backend
    re-verifies it server-side against Google's pinned
    attestation root + revocation list. Everything else — every
    `runtime.*` finding, every `integrity.*` finding, even the
    library's own `verdict_*` strings — is advisory. The chain
    bytes ship on the typed `AttestationReport` object
    (`report.app.attestation.chainB64`) for backend uploaders;
    the JSON ships only the compact actionable subset.
2.  **`integrity.art` deliberately does not memoize across
    `collect()` calls.** A cached per-process verdict would let
    any Frida / LSPosed / Zygisk attach that landed *after* the
    first collect — the common runtime-injection case — hide
    forever behind the frozen pre-attach result. Every other
    detector caches what it sensibly can for the process
    lifetime; `integrity.art` is the explicit non-cached
    counterpart. See the [Performance, threading,
    caching](#performance-threading-caching) table below.

For developers: the [`tools/red-team/`](tools/red-team/README.md)
harness ships six Frida scripts (one per `integrity.art` vector
plus the end-to-end Frida-Java hook test) that intentionally
trigger each finding, plus a README documenting the expected
`findings` for each script. Use it after a code change to verify
`integrity.art` still fires.

## Permissions

DeviceIntelligence ships with the absolute minimum permission set in the library
AAR, and every additional permission is opt-in through the Gradle plugin DSL so
consumers can decide per-app.

| Permission                       | Where it lives                                | Required by                                              | Opt-in mechanism                                  |
|----------------------------------|-----------------------------------------------|----------------------------------------------------------|---------------------------------------------------|
| `QUERY_ALL_PACKAGES`             | Library manifest (always merged in)           | `runtime.root` `root_manager_app_installed` channel      | Strip via `tools:node="remove"`                   |
| `ACCESS_NETWORK_STATE`           | Generated manifest fragment (opt-in)          | `DeviceContext.vpnActive`                                | `enableVpnDetection.set(true)` in Gradle          |
| `USE_BIOMETRIC`                  | Generated manifest fragment (opt-in)          | `DeviceContext.biometricsEnrolled`                       | `enableBiometricsDetection.set(true)` in Gradle   |

When you opt out of a permission, the affected field reports `null` rather than
`false` so backends can distinguish "no signal" from "negative signal".

`QUERY_ALL_PACKAGES` is the one to think hardest about: it's a
[Google-Play-restricted permission](https://support.google.com/googleplay/android-developer/answer/10158779)
and your Play Console submission needs to justify it under "anti-malware / device
security". If you can't or don't want to, strip it as shown above and
`runtime.root` silently degrades; the rest of the library is unaffected.

## Performance, threading, caching

| Concern              | Behavior                                                                                                                                                                                                                                               |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cold-start cost      | A manifest-merged `ContentProvider` triggers `System.loadLibrary("dicore")` and a background pre-warm pass before `Application.onCreate` runs. The first user-visible `collect()` sees cached state and returns in single-digit ms.                    |
| Hot-path `collect()` | ~tens of ms on a warm process (one APK ZIP walk dominates `integrity.apk`; `attestation.key` / `integrity.bootloader` hit cached attestation results; `runtime.environment` / `runtime.root` hit cached `/proc` parses).                                                                                                            |
| Threading            | `collect()` is safe to call from any thread. For production, call it off the main thread anyway — the *first* call after process start may not be fully warm yet.                                                                                      |
| Caching              | Most detectors cache what they sensibly can for the process lifetime (attestation chain, `/proc/self/maps` parse, `/proc/mounts` parse, root-manager lookup). **`integrity.art` is the explicit exception**: it re-evaluates on every `collect()` because a cached verdict would let post-launch Frida / LSPosed attach hide behind the frozen pre-attach result. The library deliberately does NOT cache the full report either — the consumer is the right owner of "how often". |
| Native lib size      | `libdicore.so` is built per ABI (`arm64-v8a` + `x86_64` only), with `-fvisibility=hidden`, `-ffunction-sections`, `--gc-sections`. Currently ~230-250 KB stripped per ABI for the release variant; debug builds are larger because they retain the unwind tables.                                                                                |

## The sample app

`samples/minimal/` is a single-Activity app that re-runs `DeviceIntelligence.collect`
on demand and renders the resulting report as a stack of cards (Hero, Actions,
Device, App, Findings, Detectors, JSON). It's built with programmatic Kotlin UI
(no XML, no Compose, no AndroidX dependencies) so the whole app — including the
custom dark/light palette, the wrapping chip layout, and the JSON viewer — is in
two files: `MainActivity.kt` and `Ui.kt`.

Gradle wiring matches a **JitPack consumer** (plugin + published AAR **`0.2.0`**),
not the default in-tree `project(":deviceintelligence")` substitution — see the
callout under [Add it to your own app](#add-it-to-your-own-app) and
[`samples/minimal/build.gradle.kts`](samples/minimal/build.gradle.kts)
(`disableAutoRuntimeDependency` + `implementation(libs.deviceintelligence)`).

```sh
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

The `Re-collect` button re-runs every detector and re-renders. The
`Auto · off` toggle starts a 2-second auto-recollect loop — useful
for watching `integrity.art` catch a Frida / LSPosed attach in
real time, since `integrity.art` deliberately re-evaluates on
every collect (see [`integrity.art`](docs/DETECTORS.md#integrityart)
on why caching this detector's verdict would defeat its purpose).
The auto loop is lifecycle-aware: it pauses when the activity
goes to the background and resumes on return. The `Copy JSON`
button puts the canonical JSON on the clipboard — exactly what
your backend would receive, byte for byte.

## Building from source

```sh
# Tests + sample APK
./gradlew :deviceintelligence:test :samples:minimal:assembleDebug

# Library AAR (release variant)
./gradlew :deviceintelligence:assembleRelease
# → deviceintelligence/build/outputs/aar/deviceintelligence-release.aar

# Gradle plugin (sibling project; not composite-included in root settings)
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
— see [Quickstart](#quickstart). Maven Central is not wired yet; follow
[issues](https://github.com/iamjosephmj/DeviceIntelligence/issues) for updates.

## Project layout

```
deviceintelligence/         ← runtime AAR (Kotlin + JNI native lib libdicore.so)
deviceintelligence-gradle/  ← build-time plugin (sibling project; build with `-p deviceintelligence-gradle`)
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

## Contributing

The public Kotlin surface (`DeviceIntelligence.collect`, `DeviceIntelligence.collectJson`,
plus the data classes in `Telemetry.kt`) is intentionally tiny and won't grow
without a `schema_version` bump.

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
  — semantics of `verified_boot_state` and the bootloader-lock signals
  `attestation.key` surfaces.
- [Tricky Store](https://github.com/5ec1cff/TrickyStore) and the broader LSPosed
  / Magisk research community — the bypass model `integrity.bootloader` is built around.
- [RootBeer](https://github.com/scottyab/rootbeer) and [SafetyNetSamples](https://github.com/googlesamples/android-play-safetynet)
  — prior art for the `runtime.root` signal vocabulary.
- [Frida](https://frida.re/) and [LSPosed](https://github.com/LSPosed/LSPosed)
  themselves — the canonical hooking-framework signatures
  `runtime.environment` watches for.

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
