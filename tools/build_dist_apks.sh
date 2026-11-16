#!/usr/bin/env bash
# build_dist_apks.sh — generate the full demo APK set into dist/.
#
# Outputs (each one demos a different telemetry shape):
#   minimal-debug-genuine.apk         → no findings
#   minimal-debug-farm-resigned.apk   → finding · apk_signer_mismatch
#   minimal-debug-asset-stripped.apk  → finding · fingerprint_asset_missing
#   minimal-debug-payload-injected.apk→ finding · apk_entry_added
#   minimal-debug-entry-modified.apk  → finding · apk_entry_modified
#   minimal-release-genuine.apk       → no findings (release build)
#   minimal-release-farm-resigned.apk → finding · apk_signer_mismatch (release)
#
# Variants 3-5 are re-signed with the SAME debug key as the genuine
# build, so the only thing F10 can possibly notice is the content
# tamper itself (NOT the signer flip). This proves the asset / entry
# layers fire even against an attacker who has the original signing
# key.
#
# Requires: ANDROID_HOME pointing to a build-tools that ships
# zipalign + apksigner. Tested against build-tools 36.1.0.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist"
mkdir -p "$DIST"

# ---- locate tooling ---------------------------------------------------------
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT_DIR=$(ls -1d "$ANDROID_HOME"/build-tools/* 2>/dev/null | sort -V | tail -1)
[ -n "$BT_DIR" ] || { echo "no build-tools under $ANDROID_HOME"; exit 1; }
APKSIGNER="$BT_DIR/apksigner"
ZIPALIGN="$BT_DIR/zipalign"
[ -x "$APKSIGNER" ] || { echo "missing $APKSIGNER"; exit 1; }
[ -x "$ZIPALIGN" ]  || { echo "missing $ZIPALIGN";  exit 1; }

DEBUG_KS="$HOME/.android/debug.keystore"
DEBUG_KS_PASS="android"
DEBUG_KS_ALIAS="androiddebugkey"

FAKE_KS="$ROOT/samples/minimal/keystore/fake.jks"
FAKE_KS_PASS="fakepass123"
FAKE_KS_ALIAS=$(keytool -list -v -keystore "$FAKE_KS" -storepass "$FAKE_KS_PASS" 2>/dev/null \
    | awk '/Alias name:/ { print $3; exit }')
[ -n "$FAKE_KS_ALIAS" ] || { echo "could not detect fake keystore alias"; exit 1; }

# ---- shared helpers ---------------------------------------------------------
sign_with_debug_key() {
    local in="$1" out="$2"
    "$ZIPALIGN" -p -f 4 "$in" "${in%.apk}.aligned.apk"
    "$APKSIGNER" sign \
        --ks "$DEBUG_KS" --ks-pass "pass:$DEBUG_KS_PASS" \
        --key-pass "pass:$DEBUG_KS_PASS" \
        --ks-key-alias "$DEBUG_KS_ALIAS" \
        --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
        --out "$out" "${in%.apk}.aligned.apk"
}

sign_with_fake_key() {
    local in="$1" out="$2"
    "$ZIPALIGN" -p -f 4 "$in" "${in%.apk}.aligned.apk"
    "$APKSIGNER" sign \
        --ks "$FAKE_KS" --ks-pass "pass:$FAKE_KS_PASS" \
        --key-pass "pass:$FAKE_KS_PASS" \
        --ks-key-alias "$FAKE_KS_ALIAS" \
        --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
        --out "$out" "${in%.apk}.aligned.apk"
}

# ---- 0. build the canonical debug + release APKs from Gradle ---------------
echo "==> assembling debug + release"
./gradlew :samples:minimal:assembleDebug :samples:minimal:assembleRelease -q

cp "samples/minimal/build/outputs/apk/debug/minimal-debug.apk"     "$DIST/minimal-debug-genuine.apk"
cp "samples/minimal/build/outputs/apk/release/minimal-release.apk" "$DIST/minimal-release-genuine.apk"

# Older filename layout cleanup (we used to call them just *-genuine.apk).
rm -f "$DIST/minimal-genuine.apk" "$DIST/minimal-farm-resigned.apk"

# ---- helper: produce a TAMPERED twin via a Python ZIP rewrite --------------
# Args: <input-apk> <output-apk> <kind: stripped|inject|modify> [args...]
# 'stripped' takes no extra arg (removes assets/tech.thessemaj.deviceintelligence/fingerprint.bin).
# 'inject'   takes <inner-name> <body-bytes> (writes a new entry).
# 'modify'   takes <inner-name> (corrupts the bytes of an existing entry).
#
# Re-signing happens with the SAME debug key for variants 3-5 so the
# F10 SignerMismatch path doesn't mask the content-tamper signal.
TMP="$(mktemp -d)"
trap "rm -rf '$TMP'" EXIT

zip_rewrite() {
    local in="$1" out="$2" kind="$3"; shift 3
    local arg1="${1-}" arg2="${2-}"
    python3 - "$in" "$out" "$kind" "$arg1" "$arg2" <<'PY'
import sys, zipfile
src_path, dst_path, kind, arg1, arg2 = sys.argv[1:6]
with zipfile.ZipFile(src_path, 'r') as src, \
     zipfile.ZipFile(dst_path, 'w', allowZip64=False) as dst:
    for info in src.infolist():
        # Strip any pre-existing v1 (JAR) signature; we'll re-sign
        # downstream and apksigner needs a clean META-INF.
        if info.filename.startswith('META-INF/'):
            continue
        # 'stripped' drops the fingerprint blob; everything else passes through.
        if kind == 'stripped' and info.filename == 'assets/tech.thessemaj.deviceintelligence/fingerprint.bin':
            continue
        data = src.read(info.filename)
        if kind == 'modify' and info.filename == arg1:
            # Preserve length so we don't shift any deflate boundaries
            # the v2 signature would have hashed; just XOR each byte.
            data = bytes(b ^ 0xFF for b in data)
        # Preserve original compression method so that uncompressed
        # native libs stay uncompressed (and therefore page-alignable).
        new_info = zipfile.ZipInfo(info.filename, info.date_time)
        new_info.compress_type = info.compress_type
        new_info.external_attr = info.external_attr
        new_info.create_system = info.create_system
        dst.writestr(new_info, data)
    if kind == 'inject':
        dst.writestr(arg1, arg2.encode('utf-8'))
PY
}

# ---- 1. Debug · farm-resigned ----------------------------------------------
echo "==> debug · farm-resigned"
zip_rewrite "$DIST/minimal-debug-genuine.apk" "$TMP/farm.apk" passthrough
sign_with_fake_key "$TMP/farm.apk" "$DIST/minimal-debug-farm-resigned.apk"

# ---- 2. Debug · asset-stripped ---------------------------------------------
echo "==> debug · asset-stripped (FingerprintAssetMissing)"
zip_rewrite "$DIST/minimal-debug-genuine.apk" "$TMP/stripped.apk" stripped
sign_with_debug_key "$TMP/stripped.apk" "$DIST/minimal-debug-asset-stripped.apk"

# ---- 3. Debug · payload-injected -------------------------------------------
echo "==> debug · payload-injected (EntryAdded)"
zip_rewrite "$DIST/minimal-debug-genuine.apk" "$TMP/injected.apk" inject \
    "assets/attacker_payload.txt" "owned by farm-bot 9000"
sign_with_debug_key "$TMP/injected.apk" "$DIST/minimal-debug-payload-injected.apk"

# ---- 4. Debug · entry-modified ---------------------------------------------
# kotlin/internal/internal.kotlin_builtins is small (~646 bytes) and only
# read by Kotlin reflection paths the sample never touches at startup.
# This makes it safe to corrupt: F10 fires before anything would notice.
echo "==> debug · entry-modified (EntryHashMismatch)"
zip_rewrite "$DIST/minimal-debug-genuine.apk" "$TMP/modified.apk" modify \
    "kotlin/internal/internal.kotlin_builtins"
sign_with_debug_key "$TMP/modified.apk" "$DIST/minimal-debug-entry-modified.apk"

# ---- 5. Release · farm-resigned --------------------------------------------
echo "==> release · farm-resigned"
zip_rewrite "$DIST/minimal-release-genuine.apk" "$TMP/farm-rel.apk" passthrough
sign_with_fake_key "$TMP/farm-rel.apk" "$DIST/minimal-release-farm-resigned.apk"

# ---- summary ----------------------------------------------------------------
echo
echo "=== signature summary ==="
for apk in "$DIST"/*.apk; do
    cert=$("$APKSIGNER" verify --print-certs --min-sdk-version 26 "$apk" 2>/dev/null \
        | awk -F': ' '/SHA-256/ { print $2; exit }')
    schemes=$("$APKSIGNER" verify -v --min-sdk-version 26 "$apk" 2>/dev/null \
        | awk -F': ' '/Verified using v[0-9]/ && $2 == "true" { gsub(/^Verified using /,""); gsub(/ scheme.*$/,""); printf "%s ", $0; gsub(/.*$/,"") } /Verified using v[0-9]/ {} END { print "" }')
    printf "%-44s  %s  [%s]\n" "$(basename "$apk")" "${cert:0:16}…${cert: -8}" "${schemes% }"
done
echo
ls -la "$DIST"/*.apk
