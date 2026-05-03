/*
 * CTF Flag 1 — runtime DEX injection (disk-backed variant).
 *
 * Exercises `runtime.environment`'s channel (a): drops a foreign DEX
 * onto the device under `/data/local/tmp/`, then loads it via
 * `DexClassLoader`. The detector should report:
 *   - `dex_path_outside_apk` (channel a — loader chain gained a
 *     new BaseDexClassLoader whose dex element points at a path
 *     not under the app's APK split set or dalvik-cache).
 *
 * Channel (b) may also fire with `dex_in_anonymous_mapping`
 * because ART will mint an `[anon:dalvik-classes.dex extracted
 * in memory from /data/local/tmp/flag1-payload.dex]` region for
 * the just-loaded DexClassLoader's contents — the source path is
 * outside the APK split set, so the classifier returns
 * FOREIGN_PATH.
 *
 * Usage:
 *   1. Build the payload once and push to the device:
 *        cd tools/red-team/flag1-payload && ./build-payload.sh
 *        adb push payload.dex /data/local/tmp/flag1-payload.dex
 *      (Path matches what this script expects below.)
 *   2. Get the live sample-app PID and attach this script:
 *        PID=$(frida-ps -D <device> -ai | awk '/io\.ssemaj\.sample/ {print $1}')
 *        frida -D <device> -p $PID -q -l tools/red-team/dex-injection-disk.js
 *
 * Capture criteria — Flag 1 is captured when:
 *   [baseline]   runtime.environment status=OK findings=0
 *   [post-tamper] runtime.environment status=OK findings>=1
 *                 with at least one of:
 *                   kind=dex_path_outside_apk
 *                   kind=dex_in_anonymous_mapping
 */

'use strict';

var LABEL = 'flag1-disk';
var PAYLOAD_PATH = '/data/local/tmp/flag1-payload.dex';

// runtime.environment emits many kinds beyond DEX injection.
// Keep the FLAG verdict clean by filtering to just the
// DexInjection-helper-emitted kinds.
var DEX_INJECTION_KINDS = {
    'dex_classloader_added': true,
    'dex_path_outside_apk': true,
    'dex_in_memory_loader_injected': true,
    'dex_in_anonymous_mapping': true,
    'unattributable_dex_at_baseline': true,
};
// DexClassLoader needs an optimised-DEX directory it can write
// to. The sample app's code-cache is the canonical sandboxed
// location.
var OPT_DIR = null;

setImmediate(function () {
    Java.perform(function () {
        try {
            run();
        } catch (e) {
            console.error('[' + LABEL + '] failed: ' + e + '\n' + (e.stack || ''));
        }
    });
});

function run() {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var DiCls = Java.use('io.ssemaj.deviceintelligence.DeviceIntelligence');
    var TelemetryReportCls = Java.use('io.ssemaj.deviceintelligence.TelemetryReport');
    var DetectorReportCls = Java.use('io.ssemaj.deviceintelligence.DetectorReport');
    var FindingCls = Java.use('io.ssemaj.deviceintelligence.Finding');
    var MapEntryCls = Java.use('java.util.Map$Entry');
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');

    var app = ActivityThread.currentApplication();
    if (!app) {
        console.error('[' + LABEL + '] no Application yet — wait for app launch and retry');
        return;
    }
    var ctx = app.getApplicationContext();
    OPT_DIR = ctx.getCodeCacheDir().getAbsolutePath();
    var diInstance = Java.cast(DiCls.INSTANCE.value, DiCls);

    // --- Step 1: clean baseline -----------------------------------------
    console.log('[' + LABEL + '] taking clean baseline...');
    var baselineFindings = collectRuntimeDex(
        diInstance, ctx, 'baseline',
        TelemetryReportCls, DetectorReportCls, FindingCls, MapEntryCls,
    );

    // --- Step 2: load payload from disk via DexClassLoader -------------
    console.log('[' + LABEL + '] loading ' + PAYLOAD_PATH + ' via DexClassLoader...');
    var systemLoader = Java.use('java.lang.ClassLoader').getSystemClassLoader();
    var loader;
    try {
        loader = DexClassLoader.$new(PAYLOAD_PATH, OPT_DIR, null, systemLoader);
    } catch (e) {
        console.error('[' + LABEL + '] DexClassLoader.<init> threw: ' + e);
        console.error('[' + LABEL + '] did you `adb push payload.dex ' + PAYLOAD_PATH + '`?');
        return;
    }
    console.log('[' + LABEL + '] DexClassLoader installed: ' + loader);

    try {
        var payloadClass = loader.loadClass('Payload');
        console.log('[' + LABEL + '] resolved class: ' + payloadClass.getName());
    } catch (e) {
        console.warn('[' + LABEL + '] loader.loadClass("Payload") threw: ' + e);
    }

    // --- Step 3: re-collect; runtime.environment should fire --------------------
    console.log('[' + LABEL + '] re-running collect post-injection...');
    var postFindings = collectRuntimeDex(
        diInstance, ctx, 'post-tamper',
        TelemetryReportCls, DetectorReportCls, FindingCls, MapEntryCls,
    );

    // --- Capture verdict ------------------------------------------------
    var captured = postFindings.some(function (kind) {
        return kind === 'dex_path_outside_apk'
            || kind === 'dex_in_anonymous_mapping';
    });
    if (baselineFindings.length === 0 && captured) {
        console.log('[' + LABEL + '] FLAG CAPTURED — clean baseline + path-outside-APK signal post-tamper');
    } else if (baselineFindings.length > 0) {
        console.error('[' + LABEL + '] BASELINE NOT CLEAN — ' + baselineFindings.length
            + ' runtime.environment finding(s) before tamper. Restart the app and retry.');
    } else {
        console.error('[' + LABEL + '] FLAG NOT CAPTURED — post-tamper findings did not include'
            + ' dex_path_outside_apk or dex_in_anonymous_mapping.'
            + ' Got: [' + postFindings.join(', ') + ']');
    }
}

function collectRuntimeDex(diInstance, ctx, phase, TelemetryReportCls, DetectorReportCls, FindingCls, MapEntryCls) {
    var report = Java.cast(diInstance.collectBlocking(ctx), TelemetryReportCls);
    var detectors = report.getDetectors();
    var iter = detectors.iterator();
    while (iter.hasNext()) {
        var d = Java.cast(iter.next(), DetectorReportCls);
        if (d.getId() !== 'runtime.environment') continue;
        var findings = d.getFindings();
        var dexKinds = [];
        var fIter = findings.iterator();
        var i = 0;
        while (fIter.hasNext()) {
            var f = Java.cast(fIter.next(), FindingCls);
            var kind = f.getKind();
            if (!DEX_INJECTION_KINDS[kind]) continue;
            i += 1;
            dexKinds.push(kind);
            console.log('  #' + i + ' kind=' + kind
                + ' severity=' + f.getSeverity().toString()
                + ' message="' + f.getMessage() + '"'
                + ' details=' + stringifyDetails(f, MapEntryCls));
        }
        console.log('[' + LABEL + ' ' + phase + '] runtime.environment status=' + d.getStatus().toString()
            + ' duration_ms=' + d.getDurationMs() + ' dex-injection-findings=' + dexKinds.length
            + ' (of ' + findings.size() + ' total)');
        return dexKinds;
    }
    console.error('[' + LABEL + ' ' + phase + '] runtime.environment detector not in report — wrong build?');
    return [];
}

function stringifyDetails(finding, MapEntryCls) {
    var details = finding.getDetails();
    if (!details) return '{}';
    var entries = details.entrySet().toArray();
    var pairs = [];
    for (var k = 0; k < entries.length; k++) {
        var e = Java.cast(entries[k], MapEntryCls);
        pairs.push(e.getKey() + '=' + e.getValue());
    }
    return '{' + pairs.join(', ') + '}';
}
