<h1 align="center">DeviceIntelligence</h1>

<p align="center">
  <strong>Open-source Android device-integrity SDK.</strong><br/>
  Collects APK integrity, hardware key attestation, root / hook / emulator / cloner signals into one deterministic JSON your backend can act on.<br/>
  <em>Not a RASP — it observes and reports; your backend owns the policy.</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <a href="https://jitpack.io/#iamjosephmj/DeviceIntelligence"><img alt="JitPack" src="https://jitpack.io/v/iamjosephmj/DeviceIntelligence.svg"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Android-3DDC84.svg?logo=android&logoColor=white">
  <img alt="Min SDK" src="https://img.shields.io/badge/minSdk-28-green.svg">
  <img alt="Kotlin" src="https://img.shields.io/badge/Kotlin-2.0-7F52FF.svg?logo=kotlin&logoColor=white">
  <a href="#privacy--gdpr"><img alt="GDPR-friendly" src="https://img.shields.io/badge/GDPR-friendly-2E7D32.svg"></a>
</p>

---

## Install

Distributed via [JitPack](https://jitpack.io/#iamjosephmj/DeviceIntelligence). Apply the Gradle plugin — it auto-wires the runtime AAR and bakes the build-time APK fingerprint.

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
    id("io.ssemaj.deviceintelligence") version "2.0.1"
}
```

`minSdk` 28. Ships native binaries for `arm64-v8a`, `x86_64`, and `armeabi-v7a`. `kotlinx-coroutines-android` is the only runtime dependency.

## Quick start

Four entry points — pick the one that fits your use case.

**One-shot collect** — one structured snapshot at startup.

```kotlin
lifecycleScope.launch {
    val report  = DeviceIntelligence.collect(context)        // TelemetryReport
    val json    = DeviceIntelligence.collectJson(context)    // canonical JSON
    val signals = report.toIntegritySignals()

    if (IntegritySignal.HOOKING_FRAMEWORK_DETECTED in signals) {
        // Ship to your backend, gate the action, raise a flag — your call.
    }
}
```

**Periodic observe** — a fresh snapshot every N seconds (e.g. catch a Frida agent that attaches mid-flow).

```kotlin
DeviceIntelligence.observe(context, interval = 2.seconds)
    .onEach { report -> render(report) }
    .launchIn(lifecycleScope)
```

**Cumulative session observe** — like `observe()`, but accumulates findings across emissions. A transient hook that fires once and detaches stays visible with `stillActive = false`.

```kotlin
DeviceIntelligence.observeSession(context, interval = 2.seconds)
    .onEach { session: SessionFindings ->
        render(session.findings)   // List<TrackedFinding>
        ship(session.toJson())     // canonical wire format
    }
    .launchIn(lifecycleScope)
```

Each `TrackedFinding` adds `firstSeenAtEpochMs`, `lastSeenAtEpochMs`, `observationCount`, and `stillActive` on top of the underlying `Finding`.

**Java / synchronous** — for Java consumers, worker threads, JNI bridges.

```java
TelemetryReport report = DeviceIntelligence.collectBlocking(context);
String json = DeviceIntelligence.collectJsonBlocking(context);
```

## Signals

Detectors emit granular `Finding`s; the `IntegritySignal` mapper collapses them into product-shaped verdicts you branch on.

| `IntegritySignal`                      | Meaning                                                                                  |
|----------------------------------------|------------------------------------------------------------------------------------------|
| `APK_TAMPERED`                         | APK modified, repackaged, signer mismatch, or installer not allowlisted.                  |
| `APK_FINGERPRINT_UNAVAILABLE`          | Build-time fingerprint asset missing/corrupt — no verdict either way.                     |
| `BOOTLOADER_INTEGRITY_FAILED`          | Attestation chain has anomalies, or device claims StrongBox but attests lower.            |
| `TEE_ATTESTATION_DEGRADED`             | Attestation verdict below `MEETS_STRONG_INTEGRITY` (or a CBOR/EAT leaf needing re-verify).|
| `HOOKING_FRAMEWORK_DETECTED`           | Active code hooking — Frida, Xposed/LSPosed, Pine, SandHook, Substrate, DEX injection, `.text`/GOT tampering. |
| `INJECTED_NATIVE_CODE`                 | Unknown post-baseline `.so` / anon-exec mapping (precondition for hooking).               |
| `ROOT_INDICATORS_PRESENT`              | `su`, Magisk artifacts, `test-keys`, root-manager app, Shamiko bypass, or TLS-trust-store MITM. |
| `EMULATOR_DETECTED`                    | CPU-level signals (arm64 MRS / x86_64 CPUID hypervisor bit).                              |
| `APP_CLONED`                           | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches.                    |
| `DEBUGGER_ATTACHED`                    | JVM debugger or ptrace tracer attached.                                                   |
| `DEBUG_FLAG_MISMATCH`                  | App's `FLAG_DEBUGGABLE` disagrees with `ro.debuggable`.                                   |
| `HARDWARE_ATTESTED_USERSPACE_TAMPERED` | **Strongest signal.** Verified boot **and** a userspace hook in the same report — treat as a hard block. |

```kotlin
val report = DeviceIntelligence.collect(context).toIntegritySignalReport()
when {
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

The underlying detectors (`integrity.apk`, `integrity.bootloader`, `integrity.art`, `attestation.key`, `runtime.environment`, `runtime.root`, `runtime.emulator`, `runtime.cloner`) and their finding kinds are documented in [`docs/DETECTORS.md`](docs/DETECTORS.md).

> **Not a RASP.** It never blocks sessions, kills processes, or interrupts a flow. It only observes. Build enforcement on the JSON your backend ingests; keep the policy off-device.

## Output

`collectJson(context)` returns one deterministic document with a stable `schema_version` (currently `2`). The envelope:

```jsonc
{
  "schema_version": 2,
  "library_version": "2.0.1",
  "collected_at_epoch_ms": 1777400000000,
  "device":    { /* model, abi, soc, strongbox_available, ... */ },
  "app":       { "package_name": "...", "signer_cert_sha256": ["..."], "attestation": { /* chain + verdict */ } },
  "detectors": [ { "id": "integrity.apk", "status": "ok", "findings": [] }, /* ... */ ],
  "summary":   { "total_findings": 0, "findings_by_severity": {}, "detectors_with_findings": [] }
}
```

- **`status` vs `findings`** answer different questions. `status` (`ok` / `inconclusive` / `error`) = "did the detector run?"; `findings[]` = "what did it see?". A rooted device is `status: "ok"` with a non-empty `findings[]` — drive decisions off `summary.detectors_with_findings`, not `status`.
- For every `Finding`, `kind` / `severity` / `subject` / `message` are stable; `details` is opaque diagnostic data whose keys may change without a `schema_version` bump — don't key on them server-side.
- `SessionFindings.toJson()` (from `observeSession`) adds `first_seen_at_epoch_ms` / `last_seen_at_epoch_ms` / `observation_count` / `still_active` per finding.

A full clean-device report and tripped-detector examples are in [`docs/DETECTORS.md`](docs/DETECTORS.md).

## Permissions

| Permission             | Required by                                         | Default | Opt-out / opt-in                      |
|------------------------|-----------------------------------------------------|---------|---------------------------------------|
| `QUERY_ALL_PACKAGES`   | `runtime.root` `root_manager_app_installed` channel | on      | Strip via `tools:node="remove"`       |
| `ACCESS_NETWORK_STATE` | `DeviceContext.vpnActive`                           | off     | `enableVpnDetection.set(true)`        |
| `USE_BIOMETRIC`        | `DeviceContext.biometricsEnrolled`                  | off     | `enableBiometricsDetection.set(true)` |

When opted out, `vpnActive` / `biometricsEnrolled` report `null` (not `false`).

## Try the sample

```sh
git clone https://github.com/iamjosephmj/DeviceIntelligence.git
cd DeviceIntelligence
./gradlew :samples:minimal:installDebug
adb shell am start -n io.ssemaj.sample/.MainActivity
```

## Privacy & GDPR

The SDK makes **zero network calls** and reads no GAID, `ANDROID_ID`, IMEI/IMSI, SIM serial, account, contact, or location data. The output of `collectJson(context)` stays in your process; what you upload — and where — is entirely your decision. Because the library transmits nothing, it is neither a data controller nor processor under GDPR; your app remains the sole controller for any telemetry it forwards. Every field is documented in the [output contract](#output) so you can audit exactly what exists before shipping it.

## Documentation

- [**`docs/DETECTORS.md`**](docs/DETECTORS.md) — per-detector reference: finding kinds, sample tripped JSON, costs, caveats.
- [**`NATIVE_INTEGRITY_DESIGN.md`**](NATIVE_INTEGRITY_DESIGN.md) — design of the native anti-hooking stack.
- [**`CHANGELOG.md`**](CHANGELOG.md) — version history with per-release wire-format impact.
- [**`SECURITY.md`**](SECURITY.md) — vulnerability disclosure process and supported-versions policy.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
