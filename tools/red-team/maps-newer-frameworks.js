/*
 * CTF Flag 2 — newer hook framework signatures.
 *
 * Verifies that the names of the 5 newer hook frameworks added to
 * MapsParser.HOOK_FRAMEWORK_SIGNATURES in 0.9.0 actually trip the
 * `hook_framework_present` finding when present in /proc/self/maps.
 *
 * Strategy:
 *
 *   1. For each candidate framework name, allocate a memory page
 *      via Frida's `Memory.alloc(Process.pageSize)` and rename it
 *      using `Memory.protect` + the kernel's PR_SET_VMA_ANON_NAME
 *      (the same prctl() interface ART uses to label its own
 *      anon pages). A Frida helper exposes this as
 *      `Memory.allocAndName(name, size)` since frida-tools 14+.
 *      Anonymous mappings with a custom name show up in
 *      /proc/self/maps as `[anon:<name>]`, indistinguishable from
 *      a real .so being mapped at that name from a fresh-eyes
 *      kernel perspective.
 *   2. Run `DeviceIntelligence.collectBlocking()` and look for the
 *      `hook_framework_present` finding under `runtime.environment`
 *      with `details.framework == <expected canonical name>`.
 *   3. Repeat per framework, since each hook lib has its own
 *      `canonicalName` in MapsParser.
 *
 * Capture criteria — Flag 2 is captured when ALL FIVE of the
 * frameworks below produce a `hook_framework_present` finding with
 * the expected `details.framework` value when their library name
 * appears in maps:
 *   - dobby           — `libdobby` or `dobby_bridge`
 *   - whale           — `libwhale`
 *   - yahfa           — `libyahfa`
 *   - fasthook        — `libfasthook`
 *   - il2cpp_dumper   — `libil2cppdumper` or `zygisk-il2cpp`
 *
 * Usage:
 *   PID=$(frida-ps -D <device> -ai | awk '/io\.ssemaj\.sample/ {print $1}')
 *   frida -D <device> -p $PID -q -l tools/red-team/maps-newer-frameworks.js
 *
 * The script does NOT run the actual frameworks — it only fakes
 * their NAMES in the process address space. That's enough to
 * verify the name-based detection layer; downstream layers (ART
 * vector A/E/F, GOT integrity, .text drift) would need the real
 * frameworks attached, which is a separate per-framework
 * verification project.
 */

'use strict';

var LABEL = 'flag2-newer-frameworks';

// Each entry: { name: signature-substring-to-fake,
//               expected: canonicalName MapsParser should attribute it to }
//
// We pick ONE representative substring per framework. If MapsParser
// has multiple substrings for a framework (e.g. dobby has both
// `libdobby` and `dobby_bridge`), one is enough — the framework
// trips on any-of-N match.
var CANDIDATES = [
    { name: 'libdobby.so',         expected: 'dobby' },
    { name: 'libwhale.so',         expected: 'whale' },
    { name: 'libyahfa.so',         expected: 'yahfa' },
    { name: 'libfasthook.so',      expected: 'fasthook' },
    { name: 'libil2cppdumper.so',  expected: 'il2cpp_dumper' },
];

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
    var ReDetectorCls = Java.use('io.ssemaj.deviceintelligence.internal.RuntimeEnvironmentDetector');

    var app = ActivityThread.currentApplication();
    if (!app) {
        console.error('[' + LABEL + '] no Application yet — wait for app launch and retry');
        return;
    }
    var ctx = app.getApplicationContext();
    var diInstance = Java.cast(DiCls.INSTANCE.value, DiCls);
    var reDetector = Java.cast(ReDetectorCls.INSTANCE.value, ReDetectorCls);

    // --- Step 1: name N anonymous pages with the framework signatures ---
    // Strategy: Memory.alloc gives us a fresh anonymous page; we
    // then call prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr,
    // size, name) — the same kernel interface ART uses to label
    // its own anon regions — so /proc/self/maps now shows the
    // page as `[anon:<name>]` from the parser's point of view.
    var allocations = [];
    for (var i = 0; i < CANDIDATES.length; i++) {
        var c = CANDIDATES[i];
        try {
            var page = Memory.alloc(Process.pageSize);
            setVmaAnonName(page, Process.pageSize, c.name);
            allocations.push({ candidate: c, page: page });
            console.log('[' + LABEL + '] named anon page ' + page + ' as "' + c.name + '"');
        } catch (e) {
            console.error('[' + LABEL + '] naming failed for ' + c.name + ': ' + e);
            allocations.push({ candidate: c, page: null });
        }
    }

    // --- Step 2: collect and inspect runtime.environment findings ---
    // RuntimeEnvironmentDetector caches its hook-framework scan
    // after the first evaluate (process-stable findings — see the
    // class kdoc). Drop the cache so the upcoming collect actually
    // re-reads /proc/self/maps and picks up our freshly-named anon
    // pages.
    reDetector.resetForTest();
    var report = Java.cast(diInstance.collectBlocking(ctx), TelemetryReportCls);
    var detectors = report.getDetectors();
    var iter = detectors.iterator();
    var observedFrameworks = {};
    while (iter.hasNext()) {
        var d = Java.cast(iter.next(), DetectorReportCls);
        if (d.getId() !== 'runtime.environment') continue;
        var findings = d.getFindings();
        var fIter = findings.iterator();
        while (fIter.hasNext()) {
            var f = Java.cast(fIter.next(), FindingCls);
            if (f.getKind() !== 'hook_framework_present') continue;
            var details = f.getDetails();
            var fwName = details ? details.get('framework') : null;
            if (fwName) observedFrameworks[fwName.toString()] = true;
            console.log('[' + LABEL + ']   ' + f.getKind() + ' framework=' + fwName);
        }
        break;
    }

    // --- Step 3: capture verdict ---
    var captured = [];
    var missed = [];
    for (var j = 0; j < CANDIDATES.length; j++) {
        var exp = CANDIDATES[j].expected;
        if (observedFrameworks[exp]) captured.push(exp);
        else missed.push(exp);
    }
    if (missed.length === 0) {
        console.log('[' + LABEL + '] FLAG CAPTURED — every newer framework signature fired: '
            + JSON.stringify(captured));
    } else {
        console.error('[' + LABEL + '] FLAG NOT CAPTURED — missed: ' + JSON.stringify(missed)
            + ' (captured: ' + JSON.stringify(captured) + ')');
    }
}

/**
 * prctl(PR_SET_VMA=0x53564d41, PR_SET_VMA_ANON_NAME=0, addr, size, name)
 *
 * Resolves prctl via Frida 17's Process.findGlobalExportByName (the
 * Module.getExportByName(null, ...) global-lookup form was removed
 * in Frida 17). On Android the syscall succeeds when the address is
 * page-aligned and the size covers full pages.
 */
var _prctl = null;
function setVmaAnonName(addr, size, name) {
    if (_prctl === null) {
        // Resolve via the libc module's instance method —
        // Frida 17 has tightened the global-export lookup APIs;
        // the per-module `findExportByName` is the most stable
        // form across Frida 16/17.
        var libc = Process.getModuleByName('libc.so');
        var prctlAddr = libc.findExportByName('prctl');
        _prctl = new NativeFunction(
            prctlAddr,
            'int', ['int', 'ulong', 'pointer', 'ulong', 'pointer'],
        );
    }
    var nameBuf = Memory.allocUtf8String(name);
    var PR_SET_VMA = 0x53564d41;
    var PR_SET_VMA_ANON_NAME = 0;
    var rc = _prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, nameBuf);
    if (rc !== 0) {
        throw new Error('prctl PR_SET_VMA returned ' + rc);
    }
}
