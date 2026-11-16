#pragma once
// AUTO-GENERATED from tools/registry/verdict-cores.json by
// tools/registry/gen-core-dispatch.py.
// cores-sha256: 54b890a072bdd379291d9f5ff10fa514d420a1b0c492e3d448402e1f22d9bc76
//
// The digest above is of verdict-cores.json. :deviceintelligence's
// checkCoreDispatchFresh task recomputes it and FAILS THE BUILD on a mismatch,
// so an edited manifest can no longer ship a stale dispatch block. Regenerate
// with the command above.
// DO NOT EDIT. Regenerate after changing the manifest.
//
// Each entry is a DIRECT call (no dispatch table: in anti-tamper code a
// function-pointer table is a hijack target). Appended in wire order.
#define DICORE_RUN_WIRED_CORES(append, out, critical) \
    /* runtime.root: filesystem + /proc channels; tls_trust_store_tampered is the only CRITICAL. */ \
    append(out, "root", root_verdict_records(), critical); \
    /* INTEL_0060 — dex-injection provenance across reachable class loaders. */ \
    append(out, "dex", dex_provenance_records(), critical); \
    /* INTEL_0027 — uname-vs-ABI divergence is definitional on genuine silicon. */ \
    append(out, "emulator", emu_translation_records(), critical); \
    /* INTEL_0047 — CNTVCT/CNTFRQ rate + UDF fault replay; arm64-only (empty elsewhere). */ \
    append(out, "emulator", emu_rerouting_records(), critical); \
    /* INTEL_0033 — x86_64 CPUID hypervisor evidence for hardware-virtualized emulators. */ \
    append(out, "emulator", emu_hv_records(), critical); \
    /* INTEL_0048 — arm64 device-tree/qemu_pipe markers for native-ARM VMs. */ \
    append(out, "emulator", emu_vm_platform_records(), critical); \
    /* debugger/frida surfaces + composes the four environment probes below the fold. */ \
    append(out, "environment", antidebug_verdict_records(), critical); \
    /* INTEL_0057 — kill-probe filter + self-held USER_NOTIF listener. */ \
    append(out, "seccomp", seccomp_verdict_records(), critical); \
    /* INTEL_0009 — anon/memfd/deleted executable mappings. */ \
    append(out, "environment", anon_exec_records(), critical); \
    /* INTEL_0029 — scan-channel MAC sequence/rate invariant. */ \
    append(out, "native_integrity", channel_guard_records(), critical); \
    /* INTEL_0042 — own .text vs the CMake-baked build digest. */ \
    append(out, "native_integrity", text_digest_records(), critical); \
    /* INTEL_0018 — fork-exec watchdog heartbeat evidence (seq, mac). */ \
    append(out, "native_integrity", watchdog_records(), critical); \
    /* INTEL_0012-side evidence — G10 libart .text vs on-disk file, per-site fields. */ \
    append(out, "native", native_integrity::libart_verdict_records(), critical); \
    /* own-export prologue snapshot vs live bytes. */ \
    append(out, "self_hook", prologue_verdict_records(), critical);
