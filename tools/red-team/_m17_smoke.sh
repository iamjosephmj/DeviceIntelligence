#!/usr/bin/env bash
# integrity.art final smoke harness for M17.
#
# Two-device sweep:
#
#   raven (Pixel 6 Pro, rooted, frida-server running)
#       - clean baseline + 6 vector scripts (5 vectors + frida-java
#         end-to-end). Frida attaches via PID; -n matches Frida's
#         "name" column which is the app *label*, not the package id.
#
#   caiman (Pixel 9 Pro, NOT rooted, NO frida)
#       - clean baseline only. We launch the sample, wait for the
#         on-device collect to log the full TelemetryReport JSON,
#         then grep the integrity.art detector block out of logcat.
#         Confirms integrity.art ships zero false-positives on a
#         clean production-like device.
#
# Run from repo root:
#   bash tools/red-team/_m17_smoke.sh
set -u

FRIDA=/tmp/frida-venv/bin/frida
APP=io.ssemaj.sample
HELPER=tools/red-team/_verify_helper.js
LOGDIR=build/m17
mkdir -p "$LOGDIR"

RAVEN=adb-1C291FDEE00ACV-ofEZ9R._adb-tls-connect._tcp
CAIMAN=adb-4B131FDAP006ZJ-VRzGUC._adb-tls-connect._tcp

restart_app() {
    local devid=$1
    adb -s "$devid" shell "am force-stop $APP" >/dev/null 2>&1
    sleep 1
    adb -s "$devid" shell "monkey -p $APP -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
    sleep 4
}

get_pid() {
    local devid=$1
    local pid
    for _ in 1 2 3 4 5; do
        pid=$(adb -s "$devid" shell "pidof $APP" | tr -d '\r')
        if [ -n "$pid" ]; then
            echo "$pid"
            return 0
        fi
        sleep 1
    done
    return 1
}

run_frida() {
    local devname=$1
    local devid=$2
    local label=$3
    local script=$4
    local logf=$LOGDIR/${devname}_${label}.log

    echo "================================================================"
    echo "==  $devname / $label"
    echo "================================================================"
    restart_app "$devid"
    local pid
    pid=$(get_pid "$devid") || { echo "[harness] FAIL: no pid for $APP" | tee "$logf"; return 1; }
    echo "[harness] attaching frida to pid $pid on $devname"
    timeout 25 "$FRIDA" -D "$devid" -p "$pid" \
        -l "$HELPER" -l "$script" \
        > "$logf" 2>&1
    echo "[harness] log -> $logf"
    grep -E "integrity\.art|art_method|jni_env|art_internal|F18-vector|F18-frida-java|=> integrity\.art|harness" "$logf" \
        | head -40 \
        || tail -30 "$logf"
}

run_caiman_clean() {
    local devid=$CAIMAN
    local logf=$LOGDIR/caiman_pixel9pro_clean.log

    echo "================================================================"
    echo "==  caiman_pixel9pro / clean (no-frida logcat read)"
    echo "================================================================"
    adb -s "$devid" logcat -c
    restart_app "$devid"
    sleep 5
    adb -s "$devid" logcat -d -s "DeviceIntelligence.Json:I" "DeviceIntelligence.Sample:I" "*:S" \
        > "$logf" 2>&1
    echo "[harness] log -> $logf"
    # Pull the integrity.art detector block out of the logcat-wrapped JSON.
    python3 - <<PY
import json, re, sys
text = open("$logf").read()
# Each line of the JSON is logged separately under DeviceIntelligence.Json,
# wrapped with a logcat prefix. Strip the prefix and reassemble.
keep = []
for line in text.splitlines():
    m = re.match(
        r'^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+\w\s+'
        r'DeviceIntelligence\.Json:\s?(.*)$',
        line,
    )
    if m:
        keep.append(m.group(1))
if not keep:
    print("[harness] FAIL: no DeviceIntelligence.Json lines in logcat — collect may not have run")
    sys.exit(0)
try:
    obj = json.loads("\n".join(keep))
except Exception as e:
    print(f"[harness] FAIL: could not parse JSON: {e}")
    sys.exit(0)
total = obj.get("summary", {}).get("total_findings", "?")
print(f"[harness] caiman summary.total_findings = {total}")
for d in obj.get("detectors", []):
    if d.get("id") == "integrity.art":
        n = len(d.get("findings", []))
        print(f"[harness] integrity.art status={d.get('status')} duration_ms={d.get('duration_ms')} findings={n}")
        for f in d.get("findings", []):
            print(f"           kind={f.get('kind')} severity={f.get('severity')} subject={f.get('subject')} details={f.get('details')}")
        break
else:
    print("[harness] FAIL: integrity.art not present in detectors[]")
print(f"[harness] detectors with non-empty findings:")
nonempty = [d for d in obj.get('detectors', []) if d.get('findings')]
if not nonempty:
    print("           (none)")
for d in nonempty:
    print(f"           {d['id']}: {len(d['findings'])} finding(s)")
PY
}

# ---- raven sweep -------------------------------------------------------
SCRIPTS=(
    clean:tools/red-team/_clean_baseline.js
    vector-a:tools/red-team/frida-vector-a.js
    vector-c:tools/red-team/frida-vector-c.js
    vector-d:tools/red-team/frida-vector-d.js
    vector-e:tools/red-team/frida-vector-e.js
    vector-f:tools/red-team/frida-vector-f.js
    frida-java:tools/red-team/frida-vector-frida-java.js
)

for entry in "${SCRIPTS[@]}"; do
    label=${entry%%:*}
    script=${entry#*:}
    run_frida raven_pixel6pro "$RAVEN" "$label" "$script"
done

# ---- caiman clean read --------------------------------------------------
run_caiman_clean

echo
echo "================================================================"
echo "  All smoke runs complete. Logs in $LOGDIR/"
echo "================================================================"
ls -la "$LOGDIR"
