# DeviceIntelligence 🐍

Device-integrity detection for Android. On-device detectors grade the environment — hardware attestation, verified boot, hook frameworks, root, emulators, APK tampering — and report what they find as opaque `INTEL_XXXX` codes inside a signed, encrypted token. Your backend opens it and decides.

🙏 If you like DeviceIntelligence you can show support by starring ⭐ this repository.

## Install

Apply the Gradle plugin — it adds the runtime AAR, hashes your APK at build time, and re-signs:

```kotlin
plugins {
    id("tech.thessemaj.deviceintelligence") version "0.5.2"
}
```

Provision one X25519 keypair on your machine — never in a build, never on a device:

```sh
python3 tools/keys/gen-dev-licence.py <applicationId> <out-dir>
```

Ship `server.key` as an app asset; the private half belongs to your backend. Then three calls:

```kotlin
DeviceIntelligence.initialize(application)      // once, local
DeviceIntelligence.setSession(sessionId)        // once per session, off the UI thread
val token = DeviceIntelligence.scan("checkout") // per request
myBackend.submit(token)
```

All three are suspend functions. Send the token even when the first two return false — a degraded token names the failure, and your backend grades it.

`setSession(sessionId)` is what ties a scan to a user. Your backend already knows who is logged in at login time — pass that same id here, and every token from this device names it, so the verifier can correlate the verdict with the user on the backend. It also becomes the challenge the hardware attestation binds to: the key is attested *for that session*, so a captured token cannot be replayed under another session or another user.

## Verdicts

Your backend opens tokens with the [`verifier`](verifier) module (zero-dependency Kotlin/JVM):

- **TRUSTWORTHY** — authentic and clean.
- **COMPROMISED** — authentic, but the device reports an untrustworthy state.
- **REJECT** — forged, replayed, or re-signed.

## Sample

[`samples/minimal`](samples/minimal) is a working end-to-end integration — device and backend in one process.

## Building this repo

```sh
./gradlew :samples:minimal:assembleRelease         # SDK + sample
bash tools/qa/native-unit-tests.sh                 # native unit tests
python3 tools/registry/gen-signal-ids.py --check   # signal registry drift gate
```

## License

    DeviceIntelligence — Copyright (c) 2026 Joseph James (github.com/iamjosephmj)

Licensed under [CC BY-ND 4.0](LICENSE).

---

<details>
<summary><strong>Signal catalogue — every <code>INTEL_</code> code</strong></summary>

## Signal catalogue — every `INTEL_` code

Detectors emit granular findings; the runtime collapses them into opaque `INTEL_xxxx` codes.
This is the complete catalogue — reference material for whoever writes backend policy.
The source of truth is [`tools/registry/signals-registry.json`](tools/registry/signals-registry.json)
(**append-only**: codes are never reused or renumbered, and a retired signal keeps its row).
This table is parsed by `tools/registry/gen-signal-catalogue.py`, so keep the format stable.

### Attestation — hardware identity & verified boot

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0001` | attestation | `attestation_critical` | CRITICAL | TEE key-attestation cross-checks failed (keybox reuse / device-property honeypot / revoked keybox). | **Forged hardware identity** — spoof Play Integrity `DEVICE`/`STRONG`, impersonate a genuine device, defeat hardware-key-bound checks. |
| `INTEL_0055` | attestation | `verified_boot_prop_spoof` | CRITICAL | Device self-reports green/locked boot while its hardware RootOfTrust says otherwise (TrickyStore / IntegrityBox / PIF). | **Verified-boot / Play Integrity spoofing** — a rooted device masquerades as a locked, uncompromised one. |
| `INTEL_0016` | attestation | `keybox_cross_level_reuse` | CRITICAL | StrongBox and TEE chains were signed by the *same* batch key — physically impossible on genuine hardware. | **Injected leaked keybox** — spoof hardware attestation end-to-end, defeat Play Integrity `STRONG`. |
| `INTEL_0045` | attestation | `strongbox_chain_unavailable` | VERY_LOW | StrongBox appears available but no StrongBox chain was produced — leaf claims StrongBox, or the device reports StrongBox hardware yet fell back to TEE (fail-closed). | Cross-level keybox-reuse check (`INTEL_0016`) **could not run** — possible attestation-downgrade evasion (also fires transiently on genuine HW). |
| `INTEL_0056` | attestation | `software_attested_environment` | CRITICAL | KeyDescription explicitly reports `securityLevel=Software(0)` — no hardware root of trust. | **Emulator / software keystore** — no TEE at all. |
| `INTEL_0046` | attestation | `app_identity_mismatch` | CRITICAL | The self-reported package/signer disagrees with the TEE-attested `attestationApplicationId` (tag 709). | **Repackaged or rehosted APK** — the running code is not what the attested key was issued to. |
| `INTEL_0037` | attestation | `app_not_licensed` | HIGH | Identity is self-consistent but the signing digest is not in the licensed set. | **Licensing**, not tampering — kept separate so a stale licence table can't read as a compromise. |
| `INTEL_0050` | attestation | `security_patch_stale` | MEDIUM | The **oldest** attested patch level (os/vendor/boot) is older than the backend policy window (default 365d). | **Unpatched device** — known CVEs. Backend-computed, so the window retunes without an app release. |
| `INTEL_0019` | attestation | `patch_level_self_report_mismatch` | HIGH | Self-reported patch, truncated to `YYYY-MM`, contradicts the attested `osPatchLevel`. | **Prop spoofer** faking a current patch to look healthy — same family as INTEL_0055. |
| `INTEL_0030` | attestation | `session_attestation_unavailable` | CRITICAL | `setSession()` could not produce a hardware-attested key — the TEE/StrongBox keygen failed or was hooked — so the scan carries no chain and cannot be bound to the session. Emitted degraded rather than suppressed. | **Unbound token** — nothing ties this scan to a session or to hardware, so it is replayable against another session. A hook engine that breaks keygen produces exactly this, which is why it is reported rather than met with silence. |
| `INTEL_0023` | attestation | `scan_without_session` | CRITICAL | `scan()` ran with no session id prepared: `setSession()` was never called, it failed, or it named a different session. | **Unbound token** — no session binding at all, so the result cannot be attributed to a login and is replayable. Also fires on an integration that simply skipped `setSession`, so rule out a wiring fault before reading it as an attack. |
| `INTEL_0038` | attestation | `licence_rejected_at_scan` | HIGH | The licence blob parsed but was rejected at scan time — expired, or bound to a different package. | **Licensing, or a rehosted SDK** — an expired blob is benign; one bound to another package means this SDK is running in an app it was not issued to. Grades below the other degradation codes because the benign cause is common. |
| `INTEL_0015` | attestation | `token_emitted_unsigned` | CRITICAL | No signing key was available at all — neither the attested session key nor a plain Keystore key — so the token carries an empty SIG binding. | **Unauthenticated token** — anyone able to encrypt to the server key could have minted it naming any session. Its contents must never read as evidence of a clean device. |

`INTEL_0030`–`INTEL_0015` differ in kind from the rest of this table: they are the SDK
reporting its OWN failure to bind, not a detector reporting a tamper it caught. They
exist because the alternative is silence, and at the backend silence is
indistinguishable from a network error or no SDK at all — so a degraded token that
names the failure is strictly more informative than nothing. Treat them as "this
result cannot be trusted to mean anything", not as "this device is hostile".

### Runtime instrumentation — hooks, debuggers, injected code

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0012` | art | `art_hook_critical` | CRITICAL | An ArtMethod entry point, JNIEnv table, inline prologue, or `ACC_NATIVE` bit was tampered (Xposed/LSPosed/Frida-family). | **Arbitrary Java/Kotlin method interception → in-app code injection** — steal credentials, rewrite business logic, bypass in-app checks. |
| `INTEL_0024` | native | `native_integrity_critical` | CRITICAL | Live in-memory `.text` of the native core diverged from the build-baked hash. | **Native code injection** — the detector's own logic can be patched out. |
| `INTEL_0004` | native | `libart_text_patched` | CRITICAL | libart.so's executable segment diverged from the pristine on-disk file: ART runtime code was rewritten after load. This is where Frida-Java's `implementation=` hook lands when the target is already native — it patches the `art_quick_*` dispatch trampolines and leaves the ArtMethod untouched. CRITICAL needs an absolute-jump stub branching outside libart; any other drift reports HIGH. | **Method interception no ART-level check can see** — the hook lives in the runtime's dispatch path rather than the method registry, so `INTEL_0012` cannot reach it. The stubs are hidden and absent from `.dynsym`, so no symbol-based check can either. |
| `INTEL_0034` | self_hook | `native_function_hooked` | CRITICAL | A monitored native function's prologue was overwritten with a trampoline (inline hook). | **Native function interception** — redirect calls/syscalls into injected code. |
| `INTEL_0007` | environment | `debugger_attached` | CRITICAL | A tracer/debugger is attached (non-zero TracerPid / ptrace). | **Live memory & key extraction**, step-through dynamic tampering. |
| `INTEL_0002` | environment | `frida_server_port` | CRITICAL | A frida-server listening port was found. | **Dynamic instrumentation** — hook anything in the process, full code injection. |
| `INTEL_0054` | environment | `frida_worker_thread` | CRITICAL | A frida worker thread (`pool-frida`) was found in the process. | In-process Frida instrumentation → **code injection**. |
| `INTEL_0025` | environment | `hook_framework_present` | CRITICAL | A known hook-framework library (dobby/whale/yahfa/substrate/…) was mapped in. | **Arbitrary function hooking → code injection.** |
| `INTEL_0052` | environment | `rwx_memory_mapping` | CRITICAL | A simultaneously writable+executable mapping (W^X is enforced on API ≥ 29). | **Injected shellcode / self-modifying hook staging.** |
| `INTEL_0053` | environment | `frida_memfd_jit_present` | CRITICAL | A frida memfd-backed JIT mapping was found. | Instrumentation **code injection**, staged from a hidden memfd. |
| `INTEL_0051` | dex | `foreign_dex_loaded` | CRITICAL | A DEX was loaded from an attacker-writable path. | **Runtime Java/Kotlin code injection** — load attacker classes into the app. |
| `INTEL_0000` | dex | `dex_foreign_loader` | HIGH | A dex was loaded from memory by a class loader whose parent chain excludes the app's own loader, so the app's classes are invisible to it. A dynamic-feature or DI loader is parented into the app loader precisely so its code can call back; code that cannot see the app it was loaded into is not a feature module. | **Injected code running in-process** — an agent loaded its own classes without going through the app's loader, and can run arbitrary Java and reach whatever reflection reaches, while staying outside the app's class graph. |
| `INTEL_0032` | dex | `dex_unaccounted_in_memory` | HIGH | `/proc/self/maps` shows more in-memory dex mappings than any reachable class loader claims — the trace a detached loader, held by an injector and referenced by nothing in the app, leaves behind. Compared one-directionally: ART dedupes identical dex bytes, so the mapped count can under-report, which fails safe. | **Hidden injected classes** — code is loaded into the process that no reachable loader admits to, so enumerating class loaders or allow-listing them cannot see it. |
| `INTEL_0044` | environment | `foreign_text_mapped` | HIGH | Executable code mapped from outside the legit code roots (system/apex/vendor/product/app) — e.g. a `/data/adb` module. | **Native code injection** (Zygisk/Magisk/KernelSU module) by provenance, name-independent. |
| `INTEL_0031` | environment | `got_ptr_hijack` | CRITICAL | A pointer in a system/app library's data/GOT points into injected foreign code. | **Hooked function pointer** — calls silently redirected into injected code. |
| `INTEL_0003` | environment | `libc_inline_hook` | CRITICAL | A hot libc prologue branches into injected foreign code (provenance-anchored). | **libc interception** — hide root and lie to the app about files/properties/syscalls. |
| `INTEL_0008` | environment | `libc_inline_stub` | CRITICAL | A hot libc prologue *is* an absolute-jump trampoline stub (opcode-shape, baseline-free). | **Inline libc hook that survives provenance cleanup** (Shamiko/NeoZygisk-grade) — filesystem/syscall lies. |
| `INTEL_0059` | environment | `syscall_divergence` | CRITICAL | libc reports a real system file absent while a raw `svc` syscall proves it exists. | **Filesystem cloaking** — hide root binaries / tamper artifacts from the app (behavioral, mechanism-independent). |
| `INTEL_0061` | environment | `linker_maps_divergence` | CRITICAL | The linker names a loaded `.so` whose executable VMA is an anonymous empty-path region. | **Stealth injected module with provenance erased** (NeoZygisk `spoof_virtual_maps`-class hiding). |
| `INTEL_0028` | environment | `sealed_exec_memfd` | CRITICAL | A sealed (`F_SEAL_WRITE`) *executable* memfd is mapped in. | **memfd-loaded injected module with no on-disk path** — stealth native injection (keys on seal bits, so a `jit-cache`-named decoy is still caught). |
| `INTEL_0058` | environment | `property_divergence` | CRITICAL | `__system_property_get` returns a different value than the raw property trie. | **In-process boot-state / verified-boot spoofing** at the property layer (the behavioral analog of `INTEL_0055`). |
| `INTEL_0009` | environment | `injected_executable_mapping` | HIGH | An executable mapping with no backing file, or a memfd/deleted backing: zygisk-injected stub pools (anonymous RWX), Frida gadgets (memfd), unloaded-but-mapped payloads (`(deleted)`). Kernel `vdso`/`vvar`/`vectors` pages excluded; read via raw syscall. | **Native code injection without file provenance** — code executing from mappings no clean loader produces, so path-based provenance checks (`INTEL_0044`) and the linker list (`INTEL_0061`) cannot see it. |
| `INTEL_0029` | native_integrity | `channel_sequence_anomaly` | CRITICAL | The scan channel's sequence/rate invariant was violated: every scan advances a session-key-MACed monotonic counter, and the on-device rate guard caps sweep rates — an automated 60-command drive exhausts the window. | **Scripted channel drive / capture** — the SDK is being swept by automation rather than user-driven flows, the signature of a captured or replayed integration; the MACed counter is what backend replay verification uses to detect gaps and reuse. |
| `INTEL_0018` | native_integrity | `watchdog_anomaly` | HIGH | A fork-exec'd watchdog child re-reading the parent's TracerPid every 2s went silent (child killed or silenced) or reported a live tracer. Each beat carries a keyed, consume-once (seq, mac) evidence pair. | **Anti-analysis against the detector itself** — someone is killing or ptrace-attaching an independent witness process; treat other signals from this scan as suspect. |
| `INTEL_0042` | native_integrity | `text_integrity_divergence` | CRITICAL | The library's own executable segment digest no longer matches the build-time digest baked at link — an inline hook or stub overwrite inside the SDK's own code. Per-page detail reserved for the obfuscator pass. | **The detector itself patched while running** — someone rewrote the code that reports, so every other signal from this process is suspect. Complements `INTEL_0024` (build-baked APK fingerprint) with a self-contained baseline that needs no asset. |

### Anti-analysis — syscall filtering

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0036` | seccomp | `seccomp_kill_filtered` | CRITICAL | A seccomp filter configured to kill the process on syscalls. | **Anti-instrumentation** — the process self-kills to evade analysis / sandboxing. |
| `INTEL_0040` | seccomp | `seccomp_user_notif_listener` | CRITICAL | The process holds a `SECCOMP_RET_USER_NOTIF` listener fd. | **In-process syscall interceptor** — spoof `/proc` reads (maps/status/mounts) *below libc*, hiding root from even raw-syscall probes. |

### Root & system integrity

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0005` | root | `su_binary_present` | CRITICAL | An `su` binary on `PATH` or a common location. | **Root escalation available** — unlocks essentially every tamper in this table. |
| `INTEL_0063` | root | `su_binary_system_path` | CRITICAL | An `su` binary in a protected system path. | **Strong root** → full device control. |
| `INTEL_0035` | root | `magisk_artifact_present` | CRITICAL | A Magisk file/artifact on the device. | **Systemless root** → module injection, Play-Integrity spoofing via modules. |
| `INTEL_0010` | root | `magisk_in_init_mountinfo` | CRITICAL | Magisk mount traces in init's mountinfo. | Systemless root active → **hidden module mounts** overlaying system files. |
| `INTEL_0060` | root | `magisk_daemon_socket_present` | CRITICAL | The magiskd abstract socket was found. | Live Magisk daemon → **on-demand root grants** to any app. |
| `INTEL_0021` | root | `kernelsu_present` | CRITICAL | KernelSU (kernel-level root) detected. | **Kernel-level root** — the strongest tamper; can defeat userspace detection and spoof almost anything. |
| `INTEL_0013` | root | `tls_trust_store_tampered` | CRITICAL | A tmpfs bind-mount over the conscrypt trust-store apex. | **MITM / TLS interception** — network credential and traffic theft. |
| `INTEL_0006` | root | `selinux_permissive` | CRITICAL | SELinux is not enforcing (`enforce=0`). | **Sandbox boundary removed** — cross-app data access, privilege escalation. |
| `INTEL_0057` | root | `test_keys_build` | CRITICAL | Build signed with Android test-keys (engineering build). | **Non-production / pre-rooted image** — weakened security posture. |

### Package integrity — repackaging & tamper

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0062` | apk | `apk_signer_mismatch` | CRITICAL | The running APK's signing cert ≠ the expected signer. | **Repackaged / trojanized app** — injected malware, credential harvesting inside a clone. |
| `INTEL_0022` | apk | `apk_entry_modified` | CRITICAL | A protected APK entry's bytes differ from the baked fingerprint. | **Patched app logic** / tampered resources or DEX. |
| `INTEL_0014` | apk | `apk_entry_added` | CRITICAL | An unexpected entry was added to the APK. | **Injected payload/DEX** smuggled into the package. |
| `INTEL_0017` | apk | `apk_entry_removed` | CRITICAL | An expected APK entry is missing. | **Stripped security asset** / disabled check. |
| `INTEL_0041` | apk | `fingerprint_corrupt` | CRITICAL | The baked APK fingerprint asset could not be parsed/validated. | Integrity baseline damaged — **self-check degraded**. |
| `INTEL_0043` | apk | `fingerprint_bad_magic` | CRITICAL | The fingerprint asset has an invalid magic header. | **Tampered integrity-baseline asset.** |
| `INTEL_0049` | apk | `apk_source_dir_unexpected` | MEDIUM | APK source dir isn't the expected install location. | **Side-loaded / hijacked install path.** |
| `INTEL_0026` | apk | `installer_not_whitelisted` | MEDIUM | The installing package isn't an approved store. | **Side-loaded** outside a trusted store. |

### Virtual environments — emulators & translation

| Code | detector | kind | Sev | Meaning | Reach — what it unlocks |
|---|---|---|---|---|---|
| `INTEL_0047` | emulator | `cpu_rerouting_anomaly` | CRITICAL | The process measured its own CPU being rerouted: CNTVCT does not advance at CNTFRQ (architecturally guaranteed on silicon; measured error 0.0000 on real devices), and/or a synchronous undefined-instruction fault arrived as a user-sent signal (`si_code=SI_USER` instead of `ILL_ILLOPC`). | **Hidden translation layer** — a CPU-virtualizing bridge that renamed itself and scrubbed its provenance, defeating INTEL_0027's name/provenance keys; same reach: scaled virtual devices with full app-level control. |
| `INTEL_0048` | emulator | `arm64_vm_platform` | CRITICAL | arm64 builds only: the device-tree model or compatible blob carries hypervisor-platform markers (qemu, dummy-virt, crosvm, cuttlefish, goldfish/ranchu), and/or `/dev/qemu_pipe` opens read-write. Catches full-system emulators and ARM VMs that run ARM app code natively inside an emulated ARM system — the guest ISA matches the app, so INTEL_0027 sees no divergence and INTEL_0033 (x86 CPUID) does not apply. Real devices report their SoC board and have no qemu_pipe node. | **ARM VM / full-system emulator** — the arm64 counterpart of INTEL_0033 for the class TCG/ranchu farms and cuttlefish-style VMs; fails open on unreadable files, and a fabricated device-tree defeats it (fabrication cost is the deterrent). |
| `INTEL_0033` | emulator | `hypervisor_cpu` | CRITICAL | x86_64 builds only: the CPUID hypervisor-present bit is set and/or the 0x40000000 vendor leaf answers. Detects hardware-virtualized emulators (QEMU/KVM) where guest code runs natively on the real CPU — no translation exists, so INTEL_0027 is silent by design. A real phone CPU cannot set the reserved hypervisor leaf; ARCVM/Chromebooks and WSA also set it (genuine markets). | **Hardware-virtualized environment** — the CPU itself is the emulator; scaled farms run these for free, and properties are the only spoofable layer (KVM can mask the leaf; default configs do not). |
| `INTEL_0027` | emulator | `translated_environment` | CRITICAL | Kernel ISA ≠ process ABI (raw `uname` vs compile-time ABI) — definitional binary translation — and/or a known ARM-translation bridge (`libhoudini` / `libndk_translation`) named by `ro.dalvik.vm.native.bridge` or mapped into the process. | **Scaled virtual devices** — one host running hundreds of "devices": scripted automation, replay, credential stuffing and promo abuse at near-zero marginal cost. No hardware keys (corroborate with INTEL_0056), but full app-level control. |

