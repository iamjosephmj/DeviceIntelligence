#!/usr/bin/env bash
# Compile + run every self-owned-crypto host unit test (KATs + deep edge cases).
# Pure-computation TUs, so they run off-device on the host toolchain. A host shim
# supplies a no-op android/log.h for TUs that include platform/log.h (sha256.cpp).
# Exit non-zero if any test fails — CI-friendly.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CPP="$(cd "$HERE/../../deviceintelligence/src/main/cpp" && pwd)"
C="$CPP/dicore/crypto"
CT="$CPP/test/crypto"                 # host test sources (moved out of src)
D="$CPP/dicore/detectors"
DT="$CPP/test/detectors"
PT="$CPP/test/platform"
JT="$CPP/test/jni"
OT="$CPP/test/orchestrator"
CXX="${CXX:-c++}"
SHIM="$(mktemp -d)"; mkdir -p "$SHIM/android"
cat > "$SHIM/android/log.h" <<'SH'
#pragma once
#include <cstdarg>
enum { ANDROID_LOG_VERBOSE, ANDROID_LOG_DEBUG, ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR, ANDROID_LOG_FATAL };
static inline int __android_log_print(int,const char*,const char*,...){return 0;}
static inline int __android_log_write(int,const char*,const char*){return 0;}
SH
trap 'rm -rf "$SHIM"' EXIT
TMP="$(mktemp -d)"; trap 'rm -rf "$SHIM" "$TMP"' EXIT
FLAGS="-std=c++17 -Wall -Wextra -O1 -I$CPP -I$SHIM -I$C -I$CT -I$CPP/dicore/detectors/apk/container -I$CPP/dicore/detectors/apk/identity -I$DT/detectors/apk"
rc=0
g_out="$(python3 "$HERE/detector-prose-check.py")" && echo "PASS  detector-prose  (no C string literal >= 120 chars in detectors/**.cpp)" || { echo "FAIL  detector-prose  (long literal found)"; echo "$g_out"; exit 1; }
run() { # name  <sources...>
  local name="$1"; shift
  if "$CXX" $FLAGS "$@" -o "$TMP/$name" 2>"$TMP/$name.build"; then
    if "$TMP/$name" >"$TMP/$name.out" 2>&1; then
      echo "PASS  $name  ($(tail -1 "$TMP/$name.out"))"
    else
      echo "FAIL  $name  (runtime)"; cat "$TMP/$name.out"; rc=1
    fi
  else
    echo "FAIL  $name  (build)"; cat "$TMP/$name.build"; rc=1
  fi
}
rund() { # like run(), but compiles with -DDICORE_WD_TEST=1 (test-only watchdog hooks)
  local name="$1"; shift
  if "$CXX" $FLAGS -DDICORE_WD_TEST=1 "$@" -o "$TMP/$name" 2>"$TMP/$name.build"; then
    if "$TMP/$name" >"$TMP/$name.out" 2>&1; then
      echo "PASS  $name  ($(tail -1 "$TMP/$name.out"))"
    else
      echo "FAIL  $name  (runtime)"; cat "$TMP/$name.out"; rc=1
    fi
  else
    echo "FAIL  $name  (build)"; cat "$TMP/$name.build"; rc=1
  fi
}
rund test_custody     "$OT/test_custody.cpp" "$CPP/dicore/enforce/custody.cpp" "$CPP/dicore/orchestrator/custody_wd.cpp" "$C/siphash.cpp" "$CPP/dicore/platform/string_gate.cpp" "$C/sha256.cpp"
run test_hkdf         "$CT/test_hkdf.cpp" "$C/hkdf.cpp" "$C/sha256.cpp"
run test_x25519       "$CT/test_x25519.cpp" "$C/x25519.cpp"
run test_aead_gcm     "$CT/test_aead_gcm.cpp" "$C/aead_gcm.cpp" "$C/aes_core.cpp"
run test_rand         "$CT/test_rand.cpp" "$C/rand.cpp"
run test_licence_blob "$CT/test_licence_blob.cpp" "$C/licence_blob.cpp" "$C/sha256.cpp" "$C/hkdf.cpp"
run test_fp_pepper    "$CT/test_fp_pepper.cpp" "$C/fp_pepper.cpp" "$C/sha256.cpp"
run test_raw_uname        "$PT/test_raw_uname.cpp" "$CPP/dicore/platform/syscalls.cpp"
run test_own_image        "$PT/test_own_image.cpp" "$CPP/dicore/platform/own_image.cpp" \
                          "$CPP/dicore/crypto/raw_sha256.cpp" "$CPP/dicore/platform/svc_io.cpp" \
                          "$CPP/dicore/platform/syscalls.cpp"
run test_svc_io       "$PT/test_svc_io.cpp" "$CPP/dicore/platform/svc_io.cpp" "$CPP/dicore/platform/syscalls.cpp"
run test_token_crypto "$CT/test_token_crypto.cpp" "$C/token_crypto.cpp" "$C/x25519.cpp" "$C/hkdf.cpp" "$C/aead_gcm.cpp" "$C/aes_core.cpp" "$C/rand.cpp" "$C/sha256.cpp"
run test_x509_lite    "$CT/test_x509_lite.cpp" "$C/x509_lite.cpp" "$C/sha256.cpp" "$CPP/dicore/detectors/attestation/der/attest_der.cpp"
run test_certchain    "$CT/test_certchain.cpp" "$C/certchain.cpp" "$C/x509_lite.cpp"
run test_inflate      "$CT/test_inflate.cpp" "$C/inflate.cpp"
# detector / parser host tests (pure logic, no JNI)
run test_elf_segment       "$DT/native_integrity/test_elf_segment.cpp" "$D/native_integrity/shared/elf_segment.cpp"
run test_proc_backing_parse "$DT/native_integrity/test_proc_backing_parse.cpp" "$D/native_integrity/system_libs/proc_backing_parse.cpp"
run test_channel_guard      "$DT/native_integrity/test_channel_guard.cpp" "$D/native_integrity/channel_guard.cpp" "$C/sha256.cpp"
run test_text_digest        "$DT/native_integrity/test_text_digest.cpp" "$D/native_integrity/text_digest.cpp" "$C/sha256.cpp"
run test_watchdog           "$DT/native_integrity/test_watchdog.cpp" "$D/native_integrity/watchdog.cpp" "$C/sha256.cpp"
run test_jni_cache          "$DT/native_integrity/test_jni_cache.cpp" "$CPP/dicore/jni/jni_cache.cpp"
run test_reentry_guard      "$JT/test_reentry_guard.cpp"  # header-only A2 gate
run test_seccomp_verdict   "$DT/environment/test_seccomp_verdict.cpp" "$D/environment/verdicts/seccomp_verdict.cpp"
run test_vm_markers      "$DT/emulator/test_vm_markers.cpp" -I"$CPP"

run test_maps_classify     "$DT/environment/test_maps_classify.cpp" "$D/environment/maps/maps_parse.cpp" "$CPP/dicore/platform/svc_io.cpp" "$CPP/dicore/platform/syscalls.cpp"
run test_anon_exec         "$DT/environment/test_anon_exec.cpp" "$D/environment/maps/anon_exec.cpp"
# Vector C host test: runs the real jni_env_table TU against a fake JNIEnv —
# the shim jni.h supplies the (watched-members-only) JNINativeInterface shape.
run test_jni_env_table     -I"$DT/art_integrity/shim" "$DT/art_integrity/test_jni_env_table.cpp" \
                           "$D/art_integrity/checks/jni_env_table.cpp" "$D/art_integrity/runtime/ranges.cpp" \
                           "$CPP/dicore/platform/protected_store.cpp" "$CPP/dicore/platform/svc_io.cpp" \
                           "$CPP/dicore/platform/syscalls.cpp" "$C/sha256.cpp"
run test_translation_classify "$DT/emulator/test_translation_classify.cpp" "$D/emulator/translation/translation_classify.cpp"
run test_rerouting_classify "$DT/emulator/test_rerouting_classify.cpp" "$D/emulator/translation/rerouting_classify.cpp"
run test_device_property_parse "$DT/attestation/test_device_property_parse.cpp" "$D/attestation/der/attest_der.cpp"
run test_licence_cache     "$OT/test_licence_cache.cpp" "$CPP/dicore/orchestrator/licence_cache.cpp"
run test_fingerprint_decode "$DT/apk/test_fingerprint_decode.cpp" "$D/apk/identity/fingerprint_decode.cpp"
# APK ZIP + signing-block parsers (real in-memory ZIP / real signed APK via ApkMap)
APKDEPS="$D/apk/container/apkmap.cpp $CPP/dicore/platform/syscalls.cpp $D/apk/container/zip_parser.cpp $C/sha256.cpp $CPP/dicore/platform/hex.cpp $C/inflate.cpp"
run test_zip_parser      "$DT/apk/test_zip_parser.cpp" $APKDEPS
run test_sigblock_parser "$DT/apk/test_sigblock_parser.cpp" "$D/apk/identity/sigblock_parser.cpp" $APKDEPS
# obfuscation artifact check (pass coverage of JNI registration data). Exit 77 =
# LLVM-18 toolchain absent → SKIP, not FAIL (CI without the pass).
if out="$(bash "$HERE/obf-check.sh" 2>&1)"; then
  echo "PASS  obf-check  ($(tail -1 <<<"$out"))"
elif [ "$?" -eq 77 ]; then
  echo "SKIP  obf-check  ($(tail -1 <<<"$out"))"
else
  echo "FAIL  obf-check"; printf '%s\n' "$out"; rc=1
fi
echo "-----"
[ $rc -eq 0 ] && echo "ALL NATIVE UNIT TESTS PASS" || echo "SOME TESTS FAILED"
exit $rc
