cmake_minimum_required(VERSION 3.22.1)
project(dicore C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# (mbedTLS "whitbox"/self-owned x509 REMOVED — certchain now uses the self-owned
# dicore/crypto/x509_lite parser; cryptographic chain verification is the
# backend's authority. See docs/specs/2026-08-22-mbedtls-retirement-design.md.)

# (miniz "flatbox"/self-owned inflate REMOVED — DEFLATE inflate is now the self-owned
# dicore/crypto/inflate.cpp (RFC 1951), differential-tested vs zlib.)

add_library(dicore SHARED
        dicore/platform/syscalls.cpp
        # direct-svc io (B3): vtable libc/svc backends + the shared read-file
        # state machine every sensitive /proc/self + app-file reader uses.
        dicore/platform/svc_io.cpp
        dicore/platform/safe_text_read.cpp
        dicore/platform/protected_store.cpp
        dicore/crypto/certchain.cpp
        dicore/crypto/x509_lite.cpp
        dicore/crypto/inflate.cpp
        dicore/crypto/aes_core.cpp
        dicore/crypto/aead_gcm.cpp
        dicore/crypto/hkdf.cpp
        dicore/crypto/rand.cpp
        dicore/crypto/fp_pepper.cpp
        dicore/crypto/licence_blob.cpp
        dicore/crypto/token_crypto.cpp
        dicore/crypto/x25519.cpp
        dicore/crypto/sha256.cpp
        dicore/crypto/siphash.cpp
        dicore/detectors/apk/container/apkmap.cpp
        dicore/platform/hex.cpp
        dicore/detectors/apk/container/zip_parser.cpp
        dicore/detectors/apk/identity/sigblock_parser.cpp
        dicore/jni/jni_bridge.cpp
        dicore/detectors/apk/identity/fingerprint_decode.cpp
        dicore/detectors/apk/apk_verdict.cpp
        dicore/detectors/apk/identity/dex_provenance.cpp
        dicore/detectors/attestation/der/attest_der.cpp
        dicore/detectors/attestation/attest_verdict.cpp
        dicore/detectors/attestation/policy/attest_xlevel.cpp
        dicore/detectors/attestation/policy/attest_crl.cpp
        dicore/jni/binding.cpp
        dicore/jni/jni_cache.cpp
        dicore/jni/jni_register.cpp
        # runtime.cloner — F13 readers split by responsibility: shared /proc
        # line-stream util + one TU per signal (apk-path / mount / uid), and the
        # JNI/verdict shim.
        dicore/detectors/cloner/proc/cloner_proc.cpp
        dicore/detectors/cloner/signals/signal_apk_path.cpp
        dicore/detectors/cloner/signals/signal_mount.cpp
        dicore/detectors/cloner/signals/signal_uid.cpp
        dicore/detectors/cloner/cloner_probe_jni.cpp
        dicore/detectors/root/root_probe.cpp
        dicore/detectors/environment/maps/maps_parse.cpp
        dicore/detectors/environment/maps/module_enrich.cpp
        dicore/detectors/environment/maps/trampoline.cpp
        dicore/detectors/environment/maps/maps_scan.cpp
        # runtime.environment — INTEL_0057 injected_executable_mapping: pure
        # classifier (host-tested) + the raw-syscall probe wired into
        # dicore_verdict().
        dicore/detectors/environment/maps/anon_exec.cpp
        dicore/detectors/environment/maps/anon_exec_probe.cpp
        dicore/detectors/environment/probes/syscall_divergence.cpp
        dicore/detectors/environment/probes/property_divergence.cpp
        dicore/detectors/environment/probes/linker_maps.cpp
        dicore/detectors/environment/probes/sealed_memfd.cpp
        dicore/detectors/environment/probes/hook_framework.cpp
        dicore/platform/framework_shim.cpp
        # Native keystore2 binder client (Phase 2 of the shim migration): replaces
        # the JVM keystore up-calls. SCAFFOLD — inert (fail-open) until on-device
        # verification flips its safety gate; linked now so it stays compiling.
        dicore/platform/keystore2_client.cpp
        # Native orchestrator (spec 03 §1). Formerly the single dicore_orchestrate.cpp;
        # split into orchestrate.cpp (dicore_verdict — the explicit detector list), the
        # int-counting cores (native/ART), the US-record helpers, and the
        # clean-device State/resweep lifecycle.
        #
        # A registry-driven collect() (Composite/Strategy over a DI_DETECTORS
        # X-macro) and an explicit attestation stage also lived here. Both were
        # DELETED as dead code: collect() had no callers — dicore_verdict() calls the
        # *_records() functions directly — and attestation_stage() was #included but
        # never invoked. Attestation is verified backend-side in :verifier. See
        # issue #8.
        dicore/orchestrator/licence_cache.cpp
        dicore/orchestrator/orchestrate.cpp
        dicore/orchestrator/counters.cpp
        dicore/orchestrator/record_util.cpp
        dicore/orchestrator/lifecycle.cpp
        dicore/platform/string_gate.cpp
        dicore/orchestrator/custody_wd.cpp
        dicore/enforce/custody.cpp
        # runtime.emulator — CPU-identity probe. The verdict core is ABI-neutral;
        # the matching emu_probe_*.cpp (which defines dicore::emu::probe()) is
        # appended per ABI below so the symbol is never multiply-defined.
        dicore/detectors/emulator/emu_verdict.cpp
        # runtime.emulator — INTEL_0056 translated_environment (uname-vs-ABI
        # divergence + native-bridge artifacts; pure classifier + probe).
        dicore/detectors/emulator/translation/translation_classify.cpp
        dicore/detectors/emulator/translation/translation_probe.cpp
        # runtime.emulator — INTEL_0062 hypervisor_cpu (x86_64 CPU-state probe;
        # ABI-guarded internally, contributes nothing on arm builds).
        dicore/detectors/emulator/arch/emu_hv_probe.cpp
        # runtime.emulator — INTEL_0063 arm64_vm_platform (arm64 tier-2 probe;
        # ABI-guarded internally, contributes nothing on other ABIs).
        dicore/detectors/emulator/arch/emu_vm_platform.cpp
        # runtime.emulator — INTEL_0061 cpu_rerouting_anomaly (behavioural
        # companion to INTEL_0056: counter coherence + fault fidelity; pure
        # classifier + probe).
        dicore/detectors/emulator/translation/rerouting_classify.cpp
        dicore/detectors/emulator/translation/rerouting_probe.cpp
        # runtime.environment — anti-debug / anti-Frida (ptrace tracer, frida
        # default-port probe, Frida worker-thread names). Complements the mapped-
        # trampoline scan in detectors/environment/maps/.
        dicore/detectors/environment/verdicts/antidebug_verdict.cpp
        # runtime.environment (seccomp): detect an attacker-added seccomp filter
        # neutering the watchdog's kill. kill(self,0) EPERM probe + filter-count delta.
        dicore/detectors/environment/verdicts/seccomp_verdict.cpp
        # F18 — ART integrity. M0 ships only the liveness probe; later
        # milestones add registry/offsets/ranges/snapshot/inline_prologue
        # as additional translation units inside dicore/art_integrity/.
        dicore/detectors/art_integrity/art_integrity.cpp
        dicore/detectors/art_integrity/runtime/registry.cpp
        dicore/detectors/art_integrity/runtime/offsets.cpp
        dicore/detectors/art_integrity/runtime/ranges.cpp
        dicore/detectors/art_integrity/runtime/snapshot.cpp
        dicore/detectors/art_integrity/checks/jni_env_table.cpp
        dicore/detectors/art_integrity/checks/inline_prologue.cpp
        # in-memory libart dynsym walker (extracted from inline_prologue — F18
        # Vector D symbol resolution; reusable + independently testable).
        dicore/detectors/art_integrity/runtime/libart_symtab.cpp
        dicore/detectors/art_integrity/checks/jni_entry.cpp
        dicore/detectors/art_integrity/checks/access_flags.cpp
        dicore/detectors/art_integrity/art_integrity_jni.cpp
        # the native-integrity design — anti-hooking + native
        # integrity. G1 lays down the range_map + module skeleton;
        # G2..G7 each add their own translation unit:
        #   text_verify.cpp     (G2)
        #   got_verify.cpp      (G4)
        # (G3 lib_inventory.cpp / inventory_util.cpp / anon_exec_scan.cpp were
        #  deleted — dead + redundant with INTEL_0035 foreign_text_mapped; see #8.)
        #   caller_verify.cpp   (G7)
        dicore/detectors/native_integrity/process/range_map.cpp
        dicore/detectors/native_integrity/process/baseline.cpp
        dicore/detectors/native_integrity/self/text_verify.cpp
        dicore/detectors/native_integrity/self/got_verify.cpp
        dicore/detectors/native_integrity/self/got_sections.cpp
        # libc .text integrity (G-series, libc edition): inline-hook detection on
        # libc by diffing the live segment against the on-disk file (raw syscalls).
        dicore/detectors/native_integrity/shared/elf_segment.cpp
        dicore/detectors/native_integrity/shared/module_text.cpp
        dicore/detectors/native_integrity/system_libs/libc_verify.cpp
        # libart .text integrity (G10): the same diff-vs-on-disk shape applied to
        # libart, which catches the Frida-Java hook path that patches ART's quick
        # trampolines instead of the ArtMethod (invisible to the ART registry).
        dicore/detectors/native_integrity/system_libs/libart_verify.cpp
        dicore/detectors/native_integrity/process/caller_verify.cpp
        # self-hook — inline-hook trampoline check on our own function prologues
        # (snapshot-independent; complements G2's whole-.text hash).
        dicore/detectors/native_integrity/self/prologue_verify.cpp
        # native_integrity — INTEL_0058 scan-channel sequence MAC + rate guard,
        # INTEL_0059 own-.text digest verify, and INTEL_0060 fork-exec watchdog
        # (pure host-tested cores + the probes wired into dicore_verdict()).
        dicore/detectors/native_integrity/channel_guard.cpp
        dicore/detectors/native_integrity/channel_guard_probe.cpp
        dicore/detectors/native_integrity/text_digest.cpp
        dicore/detectors/native_integrity/text_digest_probe.cpp
        # A1 digest-bound string keys: ctor-time own-image resolver (no dl*
        # calls, no heap, no libc parsers — runs from init_array before any
        # strenc ciphertext is decrypted) + the self-contained SHA-256 it
        # needs (the BoringSSL-backed one dlopens libcrypto).
        dicore/platform/own_image.cpp
        dicore/crypto/raw_sha256.cpp
        dicore/detectors/native_integrity/watchdog.cpp
        dicore/detectors/native_integrity/watchdog_probe.cpp
        # libc load-backing integrity (G9): catch a consistent on-disk libc
        # replacement by checking libc's backing device vs the verified apex mount.
        dicore/detectors/native_integrity/system_libs/proc_backing_parse.cpp
        dicore/detectors/native_integrity/system_libs/load_backing.cpp
        dicore/detectors/native_integrity/module.cpp
)

# runtime.emulator — link exactly ONE ABI-specific CPU probe (each defines the
# same dicore::emu::probe()). arm64/x86_64 get the real CPUID/CNTFRQ probes;
# every other shipped ABI (armeabi-v7a) gets the explicit "unsupported" fallback
# rather than a silent gap — attestation still catches emulators there.
if(ANDROID_ABI STREQUAL "arm64-v8a")
        target_sources(dicore PRIVATE dicore/detectors/emulator/arch/emu_probe_arm64.cpp)
elseif(ANDROID_ABI STREQUAL "x86_64")
        target_sources(dicore PRIVATE dicore/detectors/emulator/arch/emu_probe_x86_64.cpp)
else()
        target_sources(dicore PRIVATE dicore/detectors/emulator/arch/emu_probe_generic.cpp)
endif()

find_library(log-lib log)
find_library(android-lib android)
# NOTE: libbinder_ndk is NOT linked. The keystore2 client (keystore2_client.cpp)
# dlopen's it at runtime — its stub only exists at API 29+, so a link-time
# dependency would break this minSdk-28 library. dlopen loads it only on the
# API 31+ devices that have keystore2. libdl (below) provides dlopen/dlsym.

target_link_libraries(dicore
        ${log-lib}
        ${android-lib}
        dl
)

target_include_directories(dicore PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(dicore PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wno-unused-parameter
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -ffunction-sections
        -fdata-sections
        -fno-rtti
        -fno-exceptions
        -fstack-protector-strong
)

target_link_options(dicore PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        -Wl,-z,relro
        -Wl,-z,now
        # 16 KB ELF segment alignment. Required for Android 15+ on
        # devices that boot with the 16 KB page size kernel (Pixel 8a/9
        # and the API 35 / API 36 emulators); without this, the loader
        # rejects the .so with "ELF segment alignment less than page
        # size". The flag is harmless on 4 KB devices — the loader still
        # maps at 4 KB granularity, just with extra zero padding between
        # segments. Pairs with AGP's automatic `zipalign -p 16384` for
        # APK-side .so packaging (AGP 8.5+).
        -Wl,-z,max-page-size=16384
        # Force the read-only/executable segment split. AGP/NDK injects
        # -Wl,--no-rosegment, which merges .rodata AND the build-id note
        # into the single R+E LOAD — so the "executable segment" would
        # contain the very digest array INTEL_0059 bakes into .rodata (and
        # a build-id that changes every link), and no build-time digest
        # of it could ever converge. --rosegment restores the split
        # layout where the PF_X PT_LOAD is exactly .plt+.text: no
        # generated data, no notes, so the digest of its file bytes is a
        # fixed point and the runtime probe (dl_iterate_phdr PF_X)
        # hashes the identical byte range. Costs a few pages of padding.
        -Wl,--rosegment
)

# Hardening: drop the .eh_frame unwind tables. The codebase is built with
# -fno-exceptions and never calls into _Unwind, so the tables serve no
# in-process purpose — but they hand a reverser the exact start/size of
# every function (~900+ boundaries) even with the symbol table stripped.
# Tradeoff: debuggerd tombstone backtraces stop at the libdicore
# frame instead of walking through it. Flip to OFF if tombstone triage
# ever outweighs that cost.
option(DICORE_NO_UNWIND_TABLES "Emit no .eh_frame (hardening; degrades tombstone backtraces)" ON)
if(DICORE_NO_UNWIND_TABLES)
        target_compile_options(dicore PRIVATE
                -fno-asynchronous-unwind-tables
                -fno-unwind-tables
        )
endif()

# Hardening: .comment records the exact clang/LLD version — a free
# toolchain fingerprint for an analyst. The GNU build-id note is KEPT:
# it leaks nothing and crash symbolication depends on it.
add_custom_command(TARGET dicore POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} --remove-section=.comment $<TARGET_FILE:dicore>
        COMMENT "dicore: stripping .comment (toolchain fingerprint)"
)

# INTEL_0059 — bake the build-time digest of our own executable segment into
# dicore_text_digest_gen.h, consumed by text_digest_probe.cpp. The generator
# (tools/native/gen-dicore-text-digest.py) hashes the PF_X PT_LOAD file bytes
# of the just-linked .so and rewrites the header ONLY on change, so:
#   - clean build: the zero-seeded header below compiles in (the probe treats
#     all-zero as "no baseline" and skips — fail-open), the POST_BUILD step
#     writes the real digest, and the NEXT incremental build embeds it;
#   - from then on the header is stable (the digest array lives in .rodata,
#     outside the hashed segment, so embedding it cannot change the digest).
set(DICORE_TEXT_DIGEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
set(DICORE_TEXT_DIGEST_H ${DICORE_TEXT_DIGEST_DIR}/dicore_text_digest_gen.h)
if(NOT EXISTS ${DICORE_TEXT_DIGEST_H})
        file(MAKE_DIRECTORY ${DICORE_TEXT_DIGEST_DIR})
        file(WRITE ${DICORE_TEXT_DIGEST_H}
"#pragma once
// AUTO-GENERATED by tools/native/gen-dicore-text-digest.py — do not edit.
// Zero SEED written at configure time (no .so has been linked yet); the
// POST_BUILD step replaces it with the real digest. All-zero means NO
// BASELINE — the probe skips verification against it (fail-open).
#include <stdint.h>
static const uint8_t DICORE_TEXT_DIGEST[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
")
endif()
target_include_directories(dicore PRIVATE ${DICORE_TEXT_DIGEST_DIR})
find_program(DICORE_PYTHON3 python3)
if(DICORE_PYTHON3)
        add_custom_command(TARGET dicore POST_BUILD
                COMMAND ${DICORE_PYTHON3}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tools/native/gen-dicore-text-digest.py
                        $<TARGET_FILE:dicore> ${DICORE_TEXT_DIGEST_H}
                COMMENT "dicore: generating .text digest header (INTEL_0059)")
        # A1 — bind the strenc keys to this linked image's exec-page digest.
        # Re-encrypts each .dicoreobf.strtab range in place with
        # key0 XOR fold128(sha256(exec first page)) and sets the BOUND flag
        # the dicore.strdec ctors honor at load. Only .data bytes change —
        # the exec segment (and therefore the INTEL_0059 digest above) is
        # untouched, so both POST_BUILD steps are order-independent. No-op
        # when the pass did not run (debug builds: no strtab, exit 0).
        add_custom_command(TARGET dicore POST_BUILD
                COMMAND ${DICORE_PYTHON3}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tools/native/dicore-bind-strkeys.py
                        $<TARGET_FILE:dicore>
                COMMENT "dicore: binding strenc keys to exec digest (A1)")
else()
        # No python3 on the build host: the zero seed stays and the probe
        # runs in its documented fail-open "no baseline" mode. Never fatal.
        message(WARNING "python3 not found: DICORE_TEXT_DIGEST stays zeroed (INTEL_0059 fail-open)")
endif()
