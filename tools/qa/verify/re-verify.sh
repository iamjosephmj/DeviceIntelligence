#!/usr/bin/env bash
# Reverse-engineering verification harness for Project DeviceIntelligence.
# Statically inspects a built AAR or APK: native .so symbols/sections and
# plaintext strings (dex + native) that hardening should progressively remove.
# Usage: re-verify.sh <artifact.aar|apk> [label]
set -u
SDK=/home/joseph/Android/Sdk
NDK="$SDK/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin"
BT="$SDK/build-tools/36.0.0"
STRINGS="$NDK/llvm-strings"; READELF="$NDK/llvm-readelf"; NM="$NDK/llvm-nm"
DEXDUMP="$BT/dexdump"
ART="${1:?usage: re-verify.sh <artifact> [label]}"; LABEL="${2:-$(basename "$ART")}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
unzip -qo "$ART" -d "$WORK" 2>/dev/null

# Sensitive plaintext that a hardened build should NOT expose in the clear.
SENSITIVE='frida|magisk|xposed|lsposed|riru|zygisk|substrate|apk_signer_mismatch|tee_integrity|tls_trust_store_tampered|hook_framework_present|DeviceIntelligence|dicore|TracerPid'

echo "================ RE VERIFY: $LABEL ================"
# --- native .so ---
mapfile -t SOS < <(find "$WORK" -name '*.so' | sort)
echo "[native] ${#SOS[@]} .so file(s)"
for so in "${SOS[@]}"; do
  abi="$(basename "$(dirname "$so")")"
  jni=$("$NM" -D --defined-only "$so" 2>/dev/null | grep -c ' T Java_' )
  allsym=$("$NM" -D "$so" 2>/dev/null | grep -c ' T ')
  hits=$("$STRINGS" "$so" 2>/dev/null | grep -iE "$SENSITIVE" | sort -u | wc -l)
  stripped=$("$READELF" -S "$so" 2>/dev/null | grep -c '\.symtab' )
  printf "  %-13s exportedJNI=%-3s totalT=%-4s sensitiveStrHits=%-3s .symtab=%s\n" \
    "$abi" "$jni" "$allsym" "$hits" "$([ "$stripped" -gt 0 ] && echo present || echo stripped)"
done
# sample of leaking native strings (arm64 if present)
A64="$(find "$WORK" -path '*arm64*/*.so' | head -1)"
if [ -n "$A64" ]; then
  echo "[native] sample sensitive strings in arm64 .so:"
  "$STRINGS" "$A64" 2>/dev/null | grep -iE "$SENSITIVE" | sort -u | head -12 | sed 's/^/    /'
fi
# --- dex (APK only) ---
mapfile -t DEXES < <(find "$WORK" -name 'classes*.dex' | sort)
if [ "${#DEXES[@]}" -gt 0 ]; then
  echo "[dex] ${#DEXES[@]} dex file(s)"
  total=0
  for d in "${DEXES[@]}"; do
    n=$("$DEXDUMP" "$d" 2>/dev/null | grep -iE "$SENSITIVE" | wc -l); total=$((total+n))
  done
  echo "  dex sensitive-token occurrences: $total"
  "$DEXDUMP" "${DEXES[0]}" 2>/dev/null | grep -ioE "$SENSITIVE" | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'
fi
echo "=================================================="
