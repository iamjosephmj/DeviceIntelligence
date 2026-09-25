#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Native verdict cores shared by the per-detector JNIs (Kotlin-driven path) and
// the native orchestrator (dicore_orchestrate). Each returns US(0x1f)-framed Finding
// records — `kind \x1f SEVERITY \x1f ...` — so field index 1 is always the
// severity. Acquisition values (package, APK path, installer, ABI, asset bytes)
// come from the FrameworkShim up-calls; no decision lives in the JVM.

namespace dicore {

// integrity.apk: decode the baked fingerprint, hash the live APK, diff.
// First row = "__meta"; a "__status" row marks a fail-open (never CRITICAL).
std::vector<std::string> apk_verdict_records(const std::string& apkPath,
                                             const std::vector<uint8_t>& asset,
                                             const std::string& installer,
                                             const std::string& abi);

// runtime.cloner: apk-path / data-dir-mount / kernel-vs-Java-UID signals.
std::vector<std::string> cloner_verdict_records(const std::string& pkg, int javaUid);

// runtime.root: filesystem + /proc channels (tls_trust_store_tampered is the
// only CRITICAL one). The MEDIUM root-manager-app channel stays JNI-only.
std::vector<std::string> root_verdict_records();

// integrity.keyattestation: native nonce -> TEE keygen up-call -> chain verify +
// freshness + boot state. Returns the packed code: code%1000 = trust*100 +
// fresh*10 + boot (111/112/113 = VALID+fresh+affirmatively-bad boot = a kill
// case); +kAttestSoftwareOnly when fresh AND attestationSecurityLevel==Software
// (no hardware-backed evidence — also a kill case); -1 on parse/verify error.
constexpr int kAttestSoftwareOnly = 1000;
int attest_run_native();

// integrity.keyattestation (cross-level spoofer check, spec 03 prototype): attest
// a StrongBox key AND a TEE key with the same nonce and look for the
// self-contradictions a single replayed leaked keybox (TrickyStore/TEESimulator)
// can't avoid. Returns a bitmask: bit0(1) = the two BATCH (attestation-key) certs
// are identical (genuine hardware provisions StrongBox/TEE keys separately —
// ALWAYS ON, cannot false-positive); bit1(2) = on an RKP-era device (API>=33) the
// two chain ROOTS are identical (OPT-IN, build with -DDICORE_XLEVEL_RKP=1; off by
// default because its FP surface on non-RKP API>=33 devices is unvalidated). 0 =
// clean, incl. fail-open (a level unavailable / a chain unparsable).
int attest_xlevel_run();

// Device-property honeypot (v1). Status of the LAST native-driven attestation
// (attest_run_native): compares the leaf's setDevicePropertiesAttestationIncluded
// device-IDs against fw_device_identity(). Only meaningful right after
// attest_run_native(). Fail-open -> kUnavailable.
//   kMismatch : a present device-ID field differs from this device -> replayed/foreign keybox
//   kStripped : device-IDs absent on a hardware-backed (TEE/StrongBox) leaf -> request ignored
enum class DevicePropStatus { kUnavailable = 0, kClean = 1, kMismatch = 2, kStripped = 3 };
DevicePropStatus attest_device_property_status();

// integrity.keyattestation (revocation): true if the raw DER serial [serial] is in
// Google's attestation revocation list (the weekly-baked encrypted crl.bin asset).
// A revoked cert anywhere in the chain = a known-leaked keybox = spoofer. Fail-open:
// an unavailable / corrupt / un-decryptable list never revokes. See attest_crl.cpp.
bool crl_is_revoked(const uint8_t* serial, size_t len);

// runtime.environment: true if an in-process hooking-framework trampoline is
// mapped (LSPosed/YAHFA/SandHook/Frida). Feeds the attestation⇄runtime
// correlation. Read failure -> false (fail-open).
bool runtime_hooking_present();

// runtime.environment: the hook-framework maps scan surfaced as verdict records.
// scan_runtime_maps matches a mapped/anon-named hook-framework library (frida,
// dobby, whale, yahfa, fasthook, il2cpp-dumper, xposed/lsposed/substrate/…) in
// /proc/self/maps — a proof-positive signal. Emitted here as CRITICAL
// `hook_framework_present` records so they reach the verdict (the legacy path
// only fed a boot-gated bool and never counted). Empty on a clean process.
std::vector<std::string> hook_framework_records();

// runtime.environment: INTEL_0059 behavioral syscall divergence. For a set of INVARIANT
// system paths, compares libc faccessat() (which a userspace hook may intercept) against a
// RAW `svc` faccessat that bypasses libc. Flags ONLY when the raw syscall confirms the file
// exists (kernel ground truth) but libc denies it — a userspace hook lying to hide a file.
// Mechanism-independent (inline/GOT/PLT/preload) and FP-free by construction. Empty on a
// clean process. Carries hooked_symbol so the verdict can correlate it with INTEL_0003/0039.
std::vector<std::string> syscall_divergence_records();

// runtime.environment: INTEL_0061 linker<->maps divergence. dl_iterate_phdr (the dynamic
// linker's object list) vs /proc/self/maps (the kernel's view): flags a linker-named .so
// whose executable-segment base is an anonymous (empty-path) VMA — the file->anon map spoof
// (NeoZygisk `spoof_virtual_maps` / ZygiskNext-class cleanup) that erases a foreign module's
// file provenance while its soinfo stays linked. FP-free by construction; empty on a clean process.
std::vector<std::string> linker_maps_records();

// runtime.environment: INTEL_0028 sealed executable memfd. Root injectors (NeoZygisk/zygiskd)
// hand each module .so to the app as a SEALED (F_SEAL_WRITE|F_SEAL_SEAL) read-only memfd and
// dlopen it (DlopenMem), so the module never appears at a /data/adb path. Flags any mapped
// memfd that is BOTH sealed-write and executable. ART's JIT memfd is executable but writable
// (never F_SEAL_WRITE), so this is FP-safe and name-independent. Empty on a clean process.
std::vector<std::string> sealed_memfd_records();

// runtime.environment: INTEL_0058 behavioral property divergence. Compares a boot-state property
// read via libc __system_property_get (a spoofer's hook target) against the same property read
// via __system_property_find + __system_property_read_callback (bypasses the hook). A mismatch
// means __system_property_get is hooked to lie about boot state. FP-free; empty on a clean process.
std::vector<std::string> property_divergence_records();

// runtime.dex: dex-injection provenance. Flags a loaded dex whose source is not
// the app's own file-backed APK/splits — an in-memory dex (InMemoryDexClassLoader)
// or a dex loaded from an attacker-writable path — across reachable class loaders.
// CRITICAL findings; empty on a clean app. Implemented in dex_provenance.cpp.
std::vector<std::string> dex_provenance_records();

// runtime.emulator: CPU-identity probe (CNTFRQ_EL0 on arm64; CPUID hypervisor
// leaf on x86_64). Emits a single CRITICAL `runtime_emulator_cpu` record when
// the probe is decisive, else an empty vector. Defense-in-depth alongside the
// attestation software_attestation_only signal. Implemented in emu_verdict.cpp.
std::vector<std::string> emu_verdict_records();

// runtime.emulator: INTEL_0027 translated_environment. The kernel's ISA (raw
// uname) vs this process's compile-time ABI — an arm64 process on an x86
// kernel (or the reverse) is running under binary translation, which cannot
// happen on genuine silicon. Corroborating sub-facts: ro.dalvik.vm.native.bridge
// names a known translation bridge (libhoudini / libndk_translation), or that
// bridge is mapped in /proc/self/maps (read by raw syscall, so it survives a
// prop spoofer). One CRITICAL record when affirmative; clean => empty vector.
// Fail-open on every input. Implemented in translation/translation_probe.cpp.
std::vector<std::string> emu_translation_records();

// runtime.emulator: INTEL_0047 cpu_rerouting_anomaly. Behavioural companion to
// INTEL_0027: measures the rerouting a CPU-virtualizing layer cannot avoid —
// CNTVCT advancing off CNTFRQ (architecturally fixed on silicon), and a
// synchronous undefined-instruction fault replayed with a user-sent si_code.
// Fires when provenance is scrubbed and INTEL_0027's name keys are gone.
// arm64-only (the registers do not exist elsewhere); fail-open on every
// read. Implemented in translation/rerouting_probe.cpp.
std::vector<std::string> emu_rerouting_records();

// runtime.emulator: INTEL_0033 hypervisor_cpu — x86_64-only CPU-state probe
// for hardware-assisted virtualization (CPUID.1:ECX[31] + the 0x40000000
// vendor leaf). Catches emulators that hand guest code to the real CPU
// under KVM — no translation exists for INTEL_0027 to see. Honest scope:
// x86_64 Android also runs on Chromebooks (ARCVM) and WSA, which set the
// bit too; backend policy decides. Fail-open, empty on other ABIs.
// Implemented in emulator/arch/emu_hv_probe.cpp.
std::vector<std::string> emu_hv_records();

// runtime.emulator: INTEL_0048 arm64_vm_platform — arm64 tier-2 probe for
// hardware-virtualized / full-system-emulated environments (ARM KVM passes
// the host MIDR through, so there is no CPUID tell on ARM). Reads the
// device-tree model/compatible and probes /dev/qemu_pipe; markers are
// classified by the pure header (host-tested). Fail-open; arm64-only.
// Implemented in emulator/arch/emu_vm_platform.cpp.
std::vector<std::string> emu_vm_platform_records();

// runtime.environment: anti-debug / anti-Frida. Complements scan_runtime_maps
// (which catches a MAPPED hooking trampoline) with the dynamic-instrumentation
// signals it cannot see: a ptrace debugger attached (TracerPid, excluding our own
// watchdog), a frida-server listening on its default loopback ports, and Frida
// agent/gadget worker threads. Each decisive signal is one CRITICAL record; a
// clean process emits an empty vector. All probes fail-open (errno -> no record),
// so a sandboxed /proc or a missing INTERNET permission never false-positives.
// Implemented in antidebug_verdict.cpp.
std::vector<std::string> antidebug_verdict_records();

// runtime.environment (seccomp): detect a filter that actively neuters our
// syscall-based defense, EFFECT-first (we can't read an installed filter's BPF;
// it's write-only). One signal:
//   - seccomp_kill_filtered: kill(getpid(),0) returns EPERM/EACCES. Baseline
//     Android app policy permits kill(self,0), so a block = a hostile ERRNO
//     filter on kill. A benign filter (allow-all, or one not touching kill)
//     passes and is correctly ignored — no false-positive kill.
// One CRITICAL record when it fires; clean => empty. Fail-open. (A presence /
// filter-count-delta signal was removed: it can't distinguish a benign host-app
// filter from a hostile one and bricks legitimate apps for zero benefit, since
// the removed enforcement kill's wild-write detonate is unfilterable anyway.)
// Implemented in seccomp_verdict.cpp.
std::vector<std::string> seccomp_verdict_records();

// native_integrity (self-hook): scan the PROLOGUES of a curated set of our own
// high-value functions (orchestrator entry, key derivation, the kill request) for
// inline-hook trampoline opcodes — the absolute-jump stubs Dobby/Frida/Substrate
// splice over a function's first bytes. Unlike G2 (whole-.text hash vs build /
// load-time snapshot) this is self-contained: no baked hash and no snapshot
// needed, so it also catches a function that was already hooked BEFORE our load
// snapshot. Each hooked function is one CRITICAL record; a clean process emits an
// empty vector. Fail-open. Implemented in native_integrity/prologue_verify.cpp.
std::vector<std::string> prologue_verdict_records();

// runtime.environment: INTEL_0009 injected_executable_mapping. Executable
// anonymous / memfd-backed / deleted-file-backed mappings — the traces
// injected code leaves when no clean loader produced it (zygisk stub pools,
// Frida gadgets, unloaded-but-mapped payloads). Maps read via the same
// raw-syscall reader the maps scan uses; kernel vdso/vvar/vectors/vsyscall/
// uprobes excluded by the pure classifier (anon_exec.hpp, host-tested). One
// HIGH record with the region count + capped region details when any finding;
// clean => empty vector. Fail-open on unreadable maps.
// Implemented in environment/maps/anon_exec_probe.cpp.
std::vector<std::string> anon_exec_records();

// native_integrity: INTEL_0029 channel_sequence_anomaly. Advances the
// session-key-MACed monotonic chain once per scan and enforces the on-device
// rate guard — the synthetic-sweep detector (an Incognia-style 60-command
// drive exhausts the window). v1 roots the chain at a process-local random
// key (no secret session key is reachable natively at scan time); the
// token-crypto task rebinds it — see channel_guard_probe.cpp. One CRITICAL
// record per scan issued beyond the rate cap; clean => empty vector.
// Implemented in native_integrity/channel_guard_probe.cpp.
std::vector<std::string> channel_guard_records();

// native_integrity: INTEL_0042 text_integrity_divergence. SHA-256 over this
// library's own executable PT_LOAD segment (dl_iterate_phdr + safe code
// read) compared against the build-time digest baked by
// tools/native/gen-dicore-text-digest.py (dicore_text_digest_gen.h). Catches
// inline hooks and stub overwrites in the SDK's own code; per-page detail is
// reserved for the obfuscator pass. An all-zero generated digest means "no
// baseline" and skips verification; any read failure contributes nothing.
// One CRITICAL record on mismatch; clean => empty vector. Fail-open.
// Implemented in native_integrity/text_digest_probe.cpp.
std::vector<std::string> text_digest_records();

// native_integrity: INTEL_0018 watchdog_anomaly. Fork-exec'd /system/bin/sh
// watchdog child re-reads the parent's TracerPid every beat period and
// reports over a private pipe (stderr-dup2'd); the host-testable engine
// (watchdog.hpp — Spawn-injectable, time-injected) classifies 3 consecutive
// missed beats (cause=silent — child killed/silenced) or a nonzero TracerPid
// report (cause=tracer) into one HIGH record carrying a keyed-heartbeat
// (seq, mac) evidence pair (SHA-256(key||be32(seq)) truncated, constant-time,
// consume-once — INTEL_0029's anti-forgery shape). Detection-only: no kills,
// no respawn. Fail-open on spawn failure and every parse error.
// Implemented in native_integrity/watchdog_probe.cpp.
std::vector<std::string> watchdog_records();

// Pure ABI-specific predicate behind prologue_verdict_records — true if the bytes
// at `code` begin with a recognised inline-hook trampoline. Exposed for unit
// tests (synthetic trampoline buffers + real-prologue no-false-positive checks).
bool prologue_looks_hooked(const uint8_t* code);

// Fire-and-forget syscall smokescreen: launches a DETACHED thread that issues a
// burst of decoy syscalls mimicking detection probes, so an adversary tracing the
// app's syscalls cannot tell the real probes from noise. Runs in parallel with —
// and never disrupts or feeds — the challenge scan. Implemented in
// environment/antidebug_verdict.cpp. Non-blocking; safe to call and ignore.
void dicore_launch_syscall_smoke();

}  // namespace dicore
