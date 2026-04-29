/*
 * integrity.art red-team — shared "trigger an integrity.art
 * evaluate and print the findings" helper. Loaded by each
 * frida-vector-*.js script.
 *
 * Why a helper: we want each script to print the post-tamper
 * integrity.art findings as a single deterministic blob.
 * integrity.art itself re-evaluates on every
 * `DeviceIntelligence.collectBlocking()` (it deliberately does
 * not memoize across calls — see the class kdoc on
 * `ArtIntegrityDetector`), so we can simply call
 * `collectBlocking()` post-tamper and read the integrity.art
 * block out of the returned report. We use the *Blocking variant
 * because the suspend `collect()` is not directly callable from
 * Frida's Java bridge (it has a hidden `Continuation` parameter
 * at the JVM level).
 *
 * `resetForTest()` is still called below for backwards
 * compatibility with older test runs, but as of M18 it is a
 * no-op (no per-process cache to drop).
 *
 * Two-phase API:
 *   artPrepare(label)        — cache every Java/JNI ref the verify
 *                              path will need. MUST be called
 *                              BEFORE the script does anything that
 *                              tampers with the JNIEnv function
 *                              table (Vector C), otherwise the
 *                              bridge's own GetMethodID lookups
 *                              will crash mid-call.
 *   artVerifyAndReport(label)— actually call resetForTest + collect
 *                              + print findings. Reuses the cached
 *                              refs from artPrepare.
 *
 * Vector A and Vector D scripts can simply call artVerifyAndReport
 * (which auto-runs prepare on first use). Vector C must call
 * artPrepare BEFORE its tamper, then artVerifyAndReport after.
 *
 * Backwards-compatible aliases `f18Prepare` / `f18VerifyAndReport`
 * remain exported so existing red-team scripts that have not been
 * regenerated keep working.
 */

'use strict';

var artCached = null;

function artPrepare(label) {
    if (artCached) return artCached;
    var bag = {};
    Java.perform(function () {
        bag.DetectorCls = Java.use('io.ssemaj.deviceintelligence.internal.ArtIntegrityDetector');
        bag.DiCls = Java.use('io.ssemaj.deviceintelligence.DeviceIntelligence');
        bag.ActivityThread = Java.use('android.app.ActivityThread');
        bag.TelemetryReportCls = Java.use('io.ssemaj.deviceintelligence.TelemetryReport');
        bag.DetectorReportCls = Java.use('io.ssemaj.deviceintelligence.DetectorReport');
        bag.FindingCls = Java.use('io.ssemaj.deviceintelligence.Finding');
        bag.MapEntryCls = Java.use('java.util.Map$Entry');

        var app = bag.ActivityThread.currentApplication();
        if (!app) {
            console.error('[' + label + '] no Application yet — re-run after the app is fully launched');
            return;
        }
        bag.ctx = app.getApplicationContext();
        bag.detectorInstance = Java.cast(bag.DetectorCls.INSTANCE.value, bag.DetectorCls);
        bag.diInstance = Java.cast(bag.DiCls.INSTANCE.value, bag.DiCls);

        // Force Frida's Java bridge to resolve+cache the method IDs
        // we'll need post-tamper, by touching them once now. Bridge
        // implementations typically GetMethodID on first call and
        // cache for subsequent ones.
        bag.detectorInstance.resetForTest();
    });
    artCached = bag;
    return bag;
}

function artVerifyAndReport(label) {
    Java.perform(function () {
        try {
            runVerify(label);
        } catch (e) {
            console.error('[' + label + '] verify failed: ' + e + '\n' + (e.stack || ''));
        }
    });
}

function runVerify(label) {
    var bag = artPrepare(label);
    if (!bag || !bag.ctx) return;

    bag.detectorInstance.resetForTest();
    console.log('[' + label + '] integrity.art cache reset; running fresh collect...');

    // collectBlocking is the Java-friendly synchronous entry point.
    // The primary `collect(Context)` is `suspend` and therefore has
    // a Continuation parameter at the JVM level; Frida's Java bridge
    // can't synthesise one.
    var report = Java.cast(bag.diInstance.collectBlocking(bag.ctx), bag.TelemetryReportCls);
    var detectors = report.getDetectors();
    var found = false;
    var iter = detectors.iterator();
    while (iter.hasNext()) {
        var d = Java.cast(iter.next(), bag.DetectorReportCls);
        var id = d.getId();
        if (id !== 'integrity.art') continue;
        found = true;
        var findings = d.getFindings();
        var fIter = findings.iterator();
        var n = 0;
        var lines = [];
        while (fIter.hasNext()) {
            var f = Java.cast(fIter.next(), bag.FindingCls);
            n += 1;
            var details = f.getDetails();
            var detailsStr = '{}';
            if (details) {
                var entries = details.entrySet().toArray();
                var pairs = [];
                for (var k = 0; k < entries.length; k++) {
                    var e = Java.cast(entries[k], bag.MapEntryCls);
                    pairs.push(e.getKey() + '=' + e.getValue());
                }
                detailsStr = '{' + pairs.join(', ') + '}';
            }
            lines.push(
                '  #' + n + ' kind=' + f.getKind() +
                ' severity=' + f.getSeverity().toString() +
                ' subject=' + (f.getSubject() ? f.getSubject() : 'null') +
                ' message="' + f.getMessage() + '"' +
                ' details=' + detailsStr,
            );
        }
        console.log('[' + label + '] integrity.art status=' + d.getStatus().toString() +
                    ' duration_ms=' + d.getDurationMs() + ' findings=' + n);
        if (n === 0) {
            console.log('[' + label + ']   (no findings — hook may not have registered;' +
                        ' check whether snapshot was taken pre-hook)');
        } else {
            for (var i = 0; i < lines.length; i++) console.log(lines[i]);
        }
    }
    if (!found) {
        console.error('[' + label + '] integrity.art detector not present in report.detectors[] — wrong build?');
    }
}

// Backwards-compat shims for vector scripts that still reference the
// old F18 prefix. Remove after every red-team script has been updated.
var f18Prepare = artPrepare;
var f18VerifyAndReport = artVerifyAndReport;
