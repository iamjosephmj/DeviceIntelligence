#pragma once
// AUTO-GENERATED from tools/registry/signals-registry.json by
// tools/registry/gen-signal-ids.py.
// registry-sha256: 6ecaac842ee19ad240edceb6e4262ef9a81b2292a98e9fd1ddf214458badf936
//
// The digest above is of signals-registry.json. :deviceintelligence's
// checkSignalRegistryFresh task recomputes it and FAILS THE BUILD on a mismatch,
// so an edited registry can no longer ship a stale table (which would serialize
// findings as INTEL_UNKNOWN). Regenerate with the command above.
// DO NOT EDIT. Regenerate after changing the registry.
//
// Maps an internal (detector, kind) finding to the opaque wire code. Only the
// code is emitted in the token; detector/kind stay on-device. An unmapped
// finding returns "INTEL_UNKNOWN" — a loud signal that the registry is stale.
#include <string>

namespace dicore {

inline const char* signal_id(const std::string& detector, const std::string& kind) {
    if (detector == "attestation" && kind == "attestation_critical") return "INTEL_0001";
    if (detector == "art" && kind == "art_hook_critical") return "INTEL_0012";
    if (detector == "native" && kind == "native_integrity_critical") return "INTEL_0024";
    if (detector == "self_hook" && kind == "native_function_hooked") return "INTEL_0034";
    if (detector == "seccomp" && kind == "seccomp_kill_filtered") return "INTEL_0036";
    if (detector == "environment" && kind == "debugger_attached") return "INTEL_0007";
    if (detector == "environment" && kind == "frida_server_port") return "INTEL_0002";
    if (detector == "environment" && kind == "frida_worker_thread") return "INTEL_0054";
    if (detector == "environment" && kind == "hook_framework_present") return "INTEL_0025";
    if (detector == "environment" && kind == "rwx_memory_mapping") return "INTEL_0052";
    if (detector == "environment" && kind == "frida_memfd_jit_present") return "INTEL_0053";
    if (detector == "root" && kind == "su_binary_present") return "INTEL_0005";
    if (detector == "root" && kind == "su_binary_system_path") return "INTEL_0063";
    if (detector == "root" && kind == "magisk_artifact_present") return "INTEL_0035";
    if (detector == "root" && kind == "magisk_in_init_mountinfo") return "INTEL_0010";
    if (detector == "root" && kind == "magisk_daemon_socket_present") return "INTEL_0060";
    if (detector == "root" && kind == "kernelsu_present") return "INTEL_0021";
    if (detector == "root" && kind == "tls_trust_store_tampered") return "INTEL_0013";
    if (detector == "root" && kind == "selinux_permissive") return "INTEL_0006";
    if (detector == "root" && kind == "test_keys_build") return "INTEL_0057";
    if (detector == "apk" && kind == "apk_signer_mismatch") return "INTEL_0062";
    if (detector == "apk" && kind == "apk_entry_modified") return "INTEL_0022";
    if (detector == "apk" && kind == "apk_entry_added") return "INTEL_0014";
    if (detector == "apk" && kind == "apk_entry_removed") return "INTEL_0017";
    if (detector == "apk" && kind == "fingerprint_corrupt") return "INTEL_0041";
    if (detector == "apk" && kind == "fingerprint_bad_magic") return "INTEL_0043";
    if (detector == "apk" && kind == "apk_source_dir_unexpected") return "INTEL_0049";
    if (detector == "apk" && kind == "installer_not_whitelisted") return "INTEL_0026";
    if (detector == "dex" && kind == "foreign_dex_loaded") return "INTEL_0051";
    if (detector == "seccomp" && kind == "seccomp_user_notif_listener") return "INTEL_0040";
    if (detector == "attestation" && kind == "verified_boot_prop_spoof") return "INTEL_0055";
    if (detector == "attestation" && kind == "keybox_cross_level_reuse") return "INTEL_0016";
    if (detector == "attestation" && kind == "strongbox_chain_unavailable") return "INTEL_0045";
    if (detector == "environment" && kind == "foreign_text_mapped") return "INTEL_0044";
    if (detector == "environment" && kind == "got_ptr_hijack") return "INTEL_0031";
    if (detector == "environment" && kind == "libc_inline_hook") return "INTEL_0003";
    if (detector == "environment" && kind == "libc_inline_stub") return "INTEL_0008";
    if (detector == "environment" && kind == "syscall_divergence") return "INTEL_0059";
    if (detector == "environment" && kind == "linker_maps_divergence") return "INTEL_0061";
    if (detector == "environment" && kind == "sealed_exec_memfd") return "INTEL_0028";
    if (detector == "environment" && kind == "property_divergence") return "INTEL_0058";
    if (detector == "attestation" && kind == "software_attested_environment") return "INTEL_0056";
    if (detector == "attestation" && kind == "app_identity_mismatch") return "INTEL_0046";
    if (detector == "attestation" && kind == "app_not_licensed") return "INTEL_0037";
    if (detector == "attestation" && kind == "security_patch_stale") return "INTEL_0050";
    if (detector == "attestation" && kind == "patch_level_self_report_mismatch") return "INTEL_0019";
    if (detector == "dex" && kind == "dex_foreign_loader") return "INTEL_0000";
    if (detector == "dex" && kind == "dex_unaccounted_in_memory") return "INTEL_0032";
    if (detector == "native" && kind == "libart_text_patched") return "INTEL_0004";
    if (detector == "attestation" && kind == "session_attestation_unavailable") return "INTEL_0030";
    if (detector == "attestation" && kind == "scan_without_session") return "INTEL_0023";
    if (detector == "attestation" && kind == "licence_rejected_at_scan") return "INTEL_0038";
    if (detector == "attestation" && kind == "token_emitted_unsigned") return "INTEL_0015";
    if (detector == "emulator" && kind == "translated_environment") return "INTEL_0027";
    if (detector == "environment" && kind == "injected_executable_mapping") return "INTEL_0009";
    if (detector == "native_integrity" && kind == "channel_sequence_anomaly") return "INTEL_0029";
    if (detector == "native_integrity" && kind == "text_integrity_divergence") return "INTEL_0042";
    if (detector == "native_integrity" && kind == "watchdog_anomaly") return "INTEL_0018";
    if (detector == "emulator" && kind == "cpu_rerouting_anomaly") return "INTEL_0047";
    if (detector == "emulator" && kind == "hypervisor_cpu") return "INTEL_0033";
    if (detector == "emulator" && kind == "arm64_vm_platform") return "INTEL_0048";
    return "INTEL_UNKNOWN";
}

}  // namespace dicore
