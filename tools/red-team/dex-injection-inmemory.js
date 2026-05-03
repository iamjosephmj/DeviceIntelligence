/*
 * CTF Flag 1 — runtime DEX injection (in-memory variant).
 *
 * Exercises `runtime.environment`'s channel (b): loads a foreign DEX
 * into the running sample app via `InMemoryDexClassLoader`. The
 * detector should report at least one of:
 *   - `dex_in_memory_loader_injected` (channel a — loader chain
 *     gained a new BaseDexClassLoader whose dex element has no
 *     file path).
 *   - `dex_in_anonymous_mapping` (channel b — `/proc/self/maps`
 *     gained an `[anon:dalvik-classes.dex extracted in memory
 *     from <buffer>]` region after the baseline snapshot).
 *
 * Usage:
 *   1. Build the payload once:
 *        cd tools/red-team/flag1-payload && ./build-payload.sh
 *      Push it to a path the script can read into a ByteBuffer:
 *        adb push payload.dex /data/local/tmp/flag1-payload.dex
 *      The DEX bytes are ALWAYS loaded via ByteBuffer (not via
 *      DexClassLoader file path), so the on-disk location only
 *      matters for the bridge; the detector sees an in-memory
 *      load regardless.
 *   2. Get the live sample-app PID and attach this script:
 *        PID=$(frida-ps -D <device> -ai | awk '/io\.ssemaj\.sample/ {print $1}')
 *        frida -D <device> -p $PID -q -l tools/red-team/dex-injection-inmemory.js
 *
 * Capture criteria — Flag 1 is captured when:
 *   [baseline]   runtime.environment status=OK findings=0
 *   [post-tamper] runtime.environment status=OK findings>=1
 *                 with at least one of:
 *                   kind=dex_in_memory_loader_injected
 *                   kind=dex_in_anonymous_mapping
 */

'use strict';

var LABEL = 'flag1-inmemory';
var PAYLOAD_PATH = '/data/local/tmp/flag1-payload.dex';

// runtime.environment emits many finding kinds beyond DEX
// injection (hook_framework_present, rwx_memory_mapping,
// debugger_attached, native_text_drifted, ...). Filter to just
// the DEX-injection-specific kinds emitted by the DexInjection
// helper inside that detector — anything else is unrelated to
// Flag 1 and would muddy the FLAG CAPTURED verdict.
var DEX_INJECTION_KINDS = {
    'dex_classloader_added': true,
    'dex_path_outside_apk': true,
    'dex_in_memory_loader_injected': true,
    'dex_in_anonymous_mapping': true,
    'unattributable_dex_at_baseline': true,
};

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
    var ByteBuffer = Java.use('java.nio.ByteBuffer');
    var FileInputStream = Java.use('java.io.FileInputStream');
    var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
    var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');

    var app = ActivityThread.currentApplication();
    if (!app) {
        console.error('[' + LABEL + '] no Application yet — wait for app launch and retry');
        return;
    }
    var ctx = app.getApplicationContext();
    var diInstance = Java.cast(DiCls.INSTANCE.value, DiCls);

    // --- Step 1: clean baseline -----------------------------------------
    console.log('[' + LABEL + '] taking clean baseline...');
    var baselineFindings = collectRuntimeDex(
        diInstance, ctx, 'baseline',
        TelemetryReportCls, DetectorReportCls, FindingCls, MapEntryCls,
    );

    // --- Step 2: load payload bytes into a ByteBuffer -------------------
    var dexBytes = readFileBytes(PAYLOAD_PATH, FileInputStream, ByteArrayOutputStream);
    if (dexBytes === null) {
        console.error('[' + LABEL + '] could not read ' + PAYLOAD_PATH);
        console.error('[' + LABEL + '] did you `adb push payload.dex ' + PAYLOAD_PATH + '`?');
        return;
    }
    console.log('[' + LABEL + '] DEX payload size = ' + dexBytes.length + ' bytes');

    var bb = ByteBuffer.wrap(dexBytes);
    var systemLoader = Java.use('java.lang.ClassLoader').getSystemClassLoader();
    var loader = InMemoryDexClassLoader.$new(bb, systemLoader);
    console.log('[' + LABEL + '] InMemoryDexClassLoader installed: ' + loader);

    // Force ART to actually extract+register the DEX by resolving
    // a class out of it. Until we do this, ART may keep the DEX
    // bytes in the ByteBuffer without minting the named-anon
    // mapping channel (b) is looking for.
    try {
        var payloadClass = loader.loadClass('Payload');
        console.log('[' + LABEL + '] resolved class: ' + payloadClass.getName());
    } catch (e) {
        // If the user is running with a different payload class
        // name, the load will fail but the DEX is still registered
        // — the detector signal does not depend on a successful
        // class lookup.
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
        return kind === 'dex_in_memory_loader_injected'
            || kind === 'dex_in_anonymous_mapping';
    });
    if (baselineFindings.length === 0 && captured) {
        console.log('[' + LABEL + '] FLAG CAPTURED — clean baseline + injection-attributable finding(s) post-tamper');
    } else if (baselineFindings.length > 0) {
        console.error('[' + LABEL + '] BASELINE NOT CLEAN — ' + baselineFindings.length
            + ' runtime.environment finding(s) before tamper. The InitProvider may have missed its'
            + ' snapshot; restart the app and retry.');
    } else {
        console.error('[' + LABEL + '] FLAG NOT CAPTURED — post-tamper findings did not include'
            + ' dex_in_memory_loader_injected or dex_in_anonymous_mapping.'
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

function readFileBytes(path, FileInputStream, ByteArrayOutputStream) {
    try {
        var fis = FileInputStream.$new(path);
        var baos = ByteArrayOutputStream.$new();
        var buf = Java.array('byte', new Array(4096));
        var n;
        while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
        fis.close();
        var bytes = baos.toByteArray();
        return bytes;
    } catch (e) {
        return null;
    }
}
