# Changelog

All notable changes to **DeviceIntelligence** are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; the project uses [Semantic Versioning](https://semver.org/) starting at 1.0.0 — pre-1.0 entries below predate that commitment and were treated as semver-best-effort.

The wire format (`TelemetryReport` JSON, `Finding.kind` identifiers, detector IDs) carries an independent `schema_version` integer that is **only** bumped on breaking changes. Adding new finding kinds or new detectors is additive and does NOT bump `schema_version`. Backends pin against `schema_version` for correctness; library version pinning is for build-time API stability.

## [1.1.0] — 2026-05-13

### Added

- **Magisk + Shamiko hide-module bypass** (`runtime.root`). Two new finding kinds catch Magisk-hiding modules (Shamiko, etc.) that strip the cheap channels from the per-process view:
  - `magisk_in_init_mountinfo` (HIGH) — reads `/proc/1/mountinfo`. Shamiko operates by unsharing the per-process mount namespace of the target app; it cannot patch init's namespace, so a hit here while `/proc/self/mountinfo` looks clean is a strong "Magisk is hiding from us specifically" signal.
  - `magisk_daemon_socket_present` (HIGH) — scans `/proc/self/net/unix` for the `@magisk_daemon` abstract Unix socket. Bound in init's network namespace; visible to every process in the namespace, survives filesystem-artifact hides.
- **MagiskTrustUserCerts TLS-trust-store MITM detection** (`runtime.root`). New finding kind `tls_trust_store_tampered` (**CRITICAL**) trips on a `tmpfs` bind-mount over `/apex/com.android.conscrypt` in `/proc/self/mountinfo`. The mechanism is Magisk's MagiskTrustUserCerts-family modules swapping the system TLS trust store with one that accepts user-installed roots — any HTTPS the app makes after this is interceptable. Severity reflects active TLS-interception enablement, not just "root tool present". Backends should treat as a hard block for sensitive flows.
- **Frida 16+ Gum memfd-backed JIT attribution** (`runtime.environment`). New finding kind `frida_memfd_jit_present` (HIGH) fires when `/proc/self/maps` shows a `/memfd:jit-cache` mapping with `rwxp` perms AND region size > 8 MB. ART legitimately maps the same memfd path but only with `r-xp`/`r--p` perms, so the `rwxp` combination is unambiguous on Android. Fires in addition to the generic `rwx_memory_mapping` — the more specific kind lets backends pivot on Frida-only without inspecting details.
- **EAT/CBOR attestation format detection** (`attestation.key`). New finding kind `attestation_eat_format_detected` (LOW) fires when the leaf cert's `KeyDescription` extension carries CBOR-EAT bytes instead of the legacy ASN.1 `KeyDescription` SEQUENCE — common on KeyMint 200+ (Android 14+) devices using RKP-provisioned keys. Library-side parsed fields are null on those leaves; backends must re-parse the raw chain bytes (`app.attestation.chain_b64`) server-side for full field-level data. Heuristic detection only (CBOR major-type-5 header byte); full on-device CBOR-EAT decoding is tracked for a follow-up minor.
- Internal Knox extension-presence helper (`KeyAttestationDetector.hasKnoxAttestationExtension`) and `AttestationResult.Success.knoxExtensionPresent` flag carried for the follow-up minor that adds Samsung Knox warranty-bit byte parsing.

### Validation

- JVM unit tests for every new finding kind (+19 tests across `MapsParser`, `RootIndicators`, `KeyDescriptionParser`, `IntegritySignalMapper`). Pixel 6 Pro on-device validation tracked alongside the existing CTF roadmap rigs.

### Wire-format impact

Additive only. Four new `Finding.kind` strings; no detector ID renames, no `IntegritySignal` enum changes. `schema_version` stays at `2`. Backends with strict-mode kind allowlists need to add the four new strings; everything else continues working unchanged.

### Technique credits

All four channels are clean-room reimplementations from public Android security knowledge; no source borrowed:

- Shamiko-bypass, MagiskTrustUserCerts MITM, and Frida memfd-JIT signature inspired by techniques documented in the `snitchtt` project (MIT + Commons Clause — license incompatible with our Apache 2.0 distribution, so no code reuse).
- EAT format heuristic and Knox extension OID prefix referenced from `vvb2060/KeyAttestation` (Apache 2.0; cryptographic OIDs are non-copyrightable identifiers).

## [1.0.0] — 2026-05-03

First stable release. Wire format and public Kotlin API are now committed-to: additive changes only without a major version bump; breaking changes require `schema_version` increment + major version bump.

### Highlights at 1.0

- **Eight detectors**: `integrity.apk`, `integrity.bootloader`, `integrity.art`, `attestation.key`, `runtime.environment` (incl. DEX-injection channels), `runtime.root`, `runtime.emulator`, `runtime.cloner`.
- **8-layer native anti-hook stack** (G0–G7): module liveness, `.text` SHA-256, library inventory, GOT integrity, StackGuard call-stack inspection, StackWatchdog sampled inspection, JNI return-address verification.
- **12 hook framework signatures** (Frida, Cydia Substrate, Xposed, LSPosed, Riru, Zygisk, Taichi, Dobby, Whale, YAHFA, FastHook, zygisk-il2cpp-dumper).
- **Runtime DEX injection detection** (`InMemoryDexClassLoader` + `DexClassLoader` payloads) with pre-baseline timing-gap handling.
- **Three native ABIs** (`arm64-v8a`, `x86_64`, `armeabi-v7a`); `armeabi-v7a` runtime-validated on the Sauce Labs Android 11+ device farm.
- **Cumulative session API** (`observeSession()`, `SessionFindings`, `SessionFindingsAggregator`) for UIs / backends that don't want to lose sight of a transient signal the moment it stops appearing.
- **Hardware-attestation × runtime correlation** — derived `hardware_attested_but_userspace_tampered` finding when verified-boot AND hook signals fire in the same report.
- **Privacy-first analytics**: SHA-256 of `ro.build.fingerprint` for `client_id`, no PII, no package names, no memory addresses on the wire.
- **Open-source end to end** (Kotlin + native C++); zero Google Play Services dependency; works on AOSP, GrapheneOS, CalyxOS, etc.
- **Validation rig**: `tools/red-team/` Frida scripts (Vectors A–F + Frida-Java + DEX injection in-memory + DEX injection disk + newer-frameworks) plus `samples/lsposed-tester` real LSPosed module driving the same scenarios.

### Polish in 1.0

- Consolidated `unattributable_dex_at_baseline` emit shape from N findings per N regions (15 per ~4 DEX injections on Android 14+) to ONE summary finding with `region_count` / `verdict_breakdown` / `address_ranges` / `sources` details. Wire-format decision locked in for 1.x.

## [0.9.0] — 2026-05-03

### Added

- **CTF Flag 2 — five additional hook framework signatures** in `MapsParser.HOOK_FRAMEWORK_SIGNATURES`:
  - `dobby` (`libdobby`, `dobby_bridge`)
  - `whale` (`libwhale`)
  - `yahfa` (`libyahfa`)
  - `fasthook` (`libfasthook`)
  - `il2cpp_dumper` (`libil2cppdumper`, `zygisk-il2cpp`)
- `tools/red-team/maps-newer-frameworks.js` — Frida harness using `Memory.alloc` + `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)` to validate every new signature trips on the Pixel 6 Pro.
- `CTF_ROADMAP.md` Flag 2 entry rewritten with shipped-vs-deferred table.

### Deferred

- **ShadowHook** (`libshadowhook`), **SandHook** (`libsandhook`), **Pine** (`libpine`) intentionally NOT shipped — Bytedance ships ShadowHook in TikTok / Douyin / CapCut / Lemon8 for legitimate in-app patching; SandHook and Pine are used as ART-hook backends by some game-cheat-prevention frameworks. Detecting on library name alone would FP on every legitimate consumer-app install. The fix is the embedded-vs-injected distinction (cross-reference loaded library paths against the consumer's own build-time native-lib inventory captured by `Fingerprint.expectedSoList`); tracked for a future minor.

### Wire-format impact

Additive only — same `hook_framework_present` finding kind, same `IntegritySignal.HOOKING_FRAMEWORK_DETECTED` mapping. Only `details.framework` can now contain the new canonical names on attacked devices.

## [0.8.1] — 2026-05-03

### Documentation

- README "Cross-ABI stability" subsection added inside "Validated against" — confirms `armeabi-v7a` runtime-stable on Sauce Labs alongside the 64-bit ABIs. Closes the open validation item from the 0.8.0 release notes.

### Notes

- Identical binary behaviour to 0.8.0. Same wire format, same detector coverage, same `.so` contents modulo the version string.

## [0.8.0] — 2026-05-03

### Added

- **Third native ABI: `armeabi-v7a`** (32-bit ARM). Covers low-end Android devices common in EM markets that don't ship the 64-bit ABI primary or at all.
- `emu_probe_armeabi_v7a.cpp` — graceful-degrade stub for the AArch64 MRS / x86_64 CPUID emulator probes (32-bit ARM has no clean equivalent).
- `ElfParser` learns ELF32 — the build-time `.text` SHA-256 baseline now lands in `Fingerprint.dicoreTextSha256ByAbi` for all three ABIs.

### Changed

- `syscalls.cpp` on `__arm__` delegates to libc rather than issuing raw syscalls. The 32-bit Linux ARM ABI diverges from 64-bit in three places that are easy to get subtly wrong (`lseek` vs `_llseek`, `mmap` vs `mmap2`, `fstat` vs `fstat64`); routing through libc on this ABI is a documented trade — a libc-hooker can intercept these reads on 32-bit ARM that they cannot on 64-bit.
- `entry_point_offset()` returns `kUnknownOffset` on 32-bit. The `ArtMethod` field-offset table is currently 64-bit-specific; characterising 32-bit ART struct layouts across Android versions is a research task tracked for a future minor.

### Detector coverage on `armeabi-v7a`

- `integrity.apk` / `integrity.bootloader` / `attestation.key` / `runtime.environment` (incl. DEX-injection) / `runtime.root` / `runtime.cloner` — fully covered.
- `integrity.art` — `INCONCLUSIVE` (64-bit-only field offsets).
- `runtime.emulator` — non-decisive (graceful stub).

## [0.7.2] — 2026-05-03

### Documentation

- README "Cross-OEM stability" subsection added inside "Validated against" — surfaces the previously-undocumented Sauce Labs Android 11+ device-farm sweep covering Samsung One UI, Xiaomi HyperOS / MIUI, Vivo OriginOS, Honor MagicOS, OPPO ColorOS, OnePlus OxygenOS, Motorola, plus AOSP-equivalent Pixels.

## [0.7.1] — 2026-05-03

### Added

- `SessionFindings.toJson()` — canonical wire format for the cumulative session view. Parallel to `TelemetryReport.toJson()` but with per-finding session metadata embedded inline (`first_seen_at_epoch_ms`, `last_seen_at_epoch_ms`, `observation_count`, `still_active`).

### Documentation

- README "Cross-ABI stability" docs sweep + scrub stale `runtime.dex` references in `CTF_ROADMAP.md` and `FLAG1_RUNBOOK.md`.

## [0.7.0] — 2026-05-03

### Added

- **`SessionFindings` cumulative session API.** Where `observe()` emits per-tick snapshots, `observeSession()` aggregates findings across emissions and emits a `SessionFindings` snapshot tagged with first-seen / last-seen timestamps, observation count, and an active/stale flag. Use this when your UI / backend correlation should never lose sight of a signal the moment it stops appearing.
- New public types: `TrackedFinding`, `SessionFindings`, `SessionFindingsAggregator`.
- New public method: `DeviceIntelligence.observeSession(context, interval, options): Flow<SessionFindings>`.
- Sample app's Findings card refactored to use the cumulative API — active findings get `active · ×N` chip, stale findings dim to alpha 0.55 with `last seen Xs ago` chip, new "Clear" button rebuilds the aggregator.

### Wire-format impact

Additive only — runtime-only types, nothing changes in the existing `TelemetryReport.toJson()` output.

## [0.6.0] — 2026-05-03

### Added

- **CTF Flag 1 — runtime DEX-injection detection.** Catches `InMemoryDexClassLoader` / `DexClassLoader` payloads that load new bytecode without loading a foreign `.so`, patching any `ArtMethod`, or allocating an `RWX` page. Two channels:
  - **Channel (a)**: multi-root `BaseDexClassLoader` chain walk (parent + thread context loaders).
  - **Channel (b)**: `/proc/self/maps` named-anon scan recognising both Android 14+ `[anon:dalvik-DEX data]` and ≤Android 13 `[anon:dalvik-classes.dex extracted in memory from <source>]` formats.
- Pre-baseline timing-gap handling via the `unattributable_dex_at_baseline` derived finding (Zygisk-style timing where the foreign DEX is in the chain before the first-evaluate snapshot).
- Five new finding kinds: `dex_classloader_added`, `dex_path_outside_apk`, `dex_in_memory_loader_injected`, `dex_in_anonymous_mapping`, `unattributable_dex_at_baseline` — all under the existing `runtime.environment` detector ID, all mapped to `IntegritySignal.HOOKING_FRAMEWORK_DETECTED`.
- `tools/red-team/` Frida harnesses (`dex-injection-inmemory.js`, `dex-injection-disk.js`) plus `samples/lsposed-tester` real LSPosed module entries (`DexInjectionHook`, `EarlyDexInjectionHook`).

## [0.5.2] — 2026-05-02

### Fixed

- JitPack: work around `ConcurrentModificationException` on JitPack's injected `:deviceintelligence:listDeps` task (`JITPACK=true`: disable `listDeps`, disable parallel project execution).

### Added

- GitHub Packages publication workflow (`.github/workflows/publish-github-packages.yml`).

[1.1.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/1.1.0
[1.0.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/1.0.0
[0.9.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.9.0
[0.8.1]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.8.1
[0.8.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.8.0
[0.7.2]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.7.2
[0.7.1]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.7.1
[0.7.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.7.0
[0.6.0]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.6.0
[0.5.2]: https://github.com/iamjosephmj/DeviceIntelligence/releases/tag/0.5.2
