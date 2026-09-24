#!/usr/bin/env bash
# Clean-device false-positive harness.
#
# Runs the sample app (tech.thessemaj.deviceintelligence.sample) on GENUINE devices — non-rooted, no
# frida, no tamper — and asserts the verdict is FP-free: `critical=0 clean=1`
# with ZERO findings, on EVERY iteration. Any finding on a clean device is a
# candidate false positive to investigate. Multiple iterations catch
# nondeterminism (e.g. attestation flakiness).
#
# It pulls the token from the app's files dir via `run-as` (works for the
# DEBUG / debuggable build on any non-rooted device — no root needed), so use
# the debug APK. The bound token is too long for one logcat line, hence run-as.
#
# Usage (run from repo root):
#   bash tools/qa/fp-harness.sh                 # all connected devices, 5 iters
#   bash tools/qa/fp-harness.sh -s <serial> -n 10
#   bash tools/qa/fp-harness.sh --install       # adb install the debug APK first
#                                               # (retries — MIUI rate-limits installs)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
DECODE="$HERE/../red-team/decode_token.py"
APP=tech.thessemaj.deviceintelligence.sample
ITERS=${ITERS:-5}
APK=${APK:-$HERE/../../samples/minimal/build/outputs/apk/debug/minimal-debug.apk}
OUTDIR=${OUTDIR:-build/fp}
DO_INSTALL=0
SERIAL=""

while [ $# -gt 0 ]; do
    case "$1" in
        -s) SERIAL="$2"; shift 2;;
        -n) ITERS="$2"; shift 2;;
        --install) DO_INSTALL=1; shift;;
        --apk) APK="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done
mkdir -p "$OUTDIR"

devices() {
    if [ -n "$SERIAL" ]; then echo "$SERIAL"
    else adb devices | awk 'NR>1 && $2=="device"{print $1}'; fi
}

install_with_retry() {
    local s=$1
    for attempt in 1 2 3; do
        if adb -s "$s" install -r "$APK" 2>&1 | grep -q Success; then return 0; fi
        echo "  [install] attempt $attempt failed (MIUI cooldown?) — waiting 45s" >&2
        sleep 45
    done
    echo "  [install] gave up — using the already-installed app if present" >&2
    return 1
}

run_device() {
    local s=$1
    local brand model api rooted ddir
    brand=$(adb -s "$s" shell getprop ro.product.brand | tr -d '\r')
    model=$(adb -s "$s" shell getprop ro.product.model | tr -d '\r')
    api=$(adb -s "$s" shell getprop ro.build.version.sdk | tr -d '\r')
    # A clean device is one where `su` does NOT grant uid 0.
    rooted=$(adb -s "$s" shell 'su -c id 2>/dev/null' | grep -c 'uid=0' | tr -d '\r')
    ddir="$OUTDIR/$s"; mkdir -p "$ddir"
    echo "=== $s  $brand $model  API $api  rooted=$rooted ==="
    printf '{"serial":"%s","brand":"%s","model":"%s","api":"%s","rooted":"%s"}\n' \
        "$s" "$brand" "$model" "$api" "$rooted" > "$ddir/meta.json"

    [ "$DO_INSTALL" = "1" ] && install_with_retry "$s"
    if ! adb -s "$s" shell pm list packages 2>/dev/null | grep -q "$APP"; then
        echo "  [skip] $APP not installed — run with --install or install the debug APK first"
        return
    fi

    rm -f "$ddir"/iter*.json
    for i in $(seq 1 "$ITERS"); do
        adb -s "$s" shell am force-stop "$APP" >/dev/null 2>&1
        adb -s "$s" shell monkey -p "$APP" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
        sleep 4
        # Poll for the token — MIUI/first-launch cold start can outlast a fixed wait.
        local tok=""
        for _ in 1 2 3 4 5 6 7 8; do
            tok=$(adb -s "$s" shell run-as "$APP" cat files/token.txt 2>/dev/null | tr -d '\r\n ')
            printf '%s' "$tok" | grep -qE '^([0-9a-f]{2})+$' && break
            sleep 2
        done
        if ! printf '%s' "$tok" | grep -qE '^([0-9a-f]{2})+$'; then
            echo "  iter $i: NO TOKEN (run-as failed — is this the debuggable debug build?)"
            echo '{"ok":false,"error":"no token"}' > "$ddir/iter$i.json"
            continue
        fi
        python3 "$DECODE" "$tok" --json > "$ddir/iter$i.json"
        python3 - "$ddir/iter$i.json" "$i" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(f"  iter {sys.argv[2]}: critical={d.get('critical')} clean={d.get('clean')} "
      f"findings={len(d.get('findings',[]))}")
PY
    done
}

for s in $(devices); do run_device "$s"; done

echo
echo "================================================================"
python3 "$HERE/fp_report.py" "$OUTDIR" | tee "$OUTDIR/FP-REPORT.md"
