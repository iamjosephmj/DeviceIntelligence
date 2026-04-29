/*
 * F18 — real Frida-Java `cls.method.implementation = ...` hook.
 *
 * This is the canonical attack F18 Vectors E + F were built to
 * catch. Every Frida tutorial since 2017 starts with the same
 * snippet:
 *
 *   var Cls = Java.use('java.lang.X');
 *   Cls.method.implementation = function () { ... };
 *
 * Under the hood, `cls.method.implementation = ...` does two
 * things to the target ArtMethod:
 *
 *   1. Writes a Frida bridge function pointer into
 *      `entry_point_from_jni_` (the `data_` slot).
 *      → caught by Vector E (drift on snap_was_native, OR
 *        out_of_range on libart→unknown transition).
 *
 *   2. For non-native target methods, flips `ACC_NATIVE` ON in
 *      `access_flags_` so ART routes the dispatch through the
 *      JNI bridge slot.
 *      → caught by Vector F (`art_method_acc_native_flipped_on`).
 *
 * Vector A (entry_point_from_quick_compiled_code_) does NOT
 * touch the same slot, so Frida-Java is invisible to Vector A
 * by design — that gap is exactly what E and F close.
 *
 * Target choice: `String#length` is a non-native JDK method in
 * F18's frozen registry. Hooking it with Java.use lets us verify
 * BOTH vectors fire on the same record (E catches the bridge
 * pointer write, F catches the bit flip).
 *
 * Crash-safety: Frida-Java's bridge needs `String#length` to be
 * callable for its own internal bookkeeping (Object.toString
 * etc all eventually call String.length). To keep the tamper
 * window safe, we install an implementation that simply forwards
 * to `this.length()` when called — same observable behaviour,
 * but the ArtMethod fields are still tampered as far as F18 is
 * concerned.
 *
 * Usage:
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-frida-java.js
 *
 * Expected output (BOTH should fire):
 *   art_method_acc_native_flipped_on (HIGH) on String#length     ← Vector F
 *   art_method_jni_entry_drifted (HIGH) on String#length         ← Vector E
 *   art_method_jni_entry_out_of_range (HIGH) on String#length    ← Vector E (likely)
 */

'use strict';

function describeRecord(label, columns, parts) {
    var pairs = [];
    for (var i = 0; i < columns.length && i < parts.length; i++) {
        pairs.push(columns[i] + '=' + parts[i]);
    }
    console.log('[F18-frida-java]   ' + label + ' ' + pairs.join(' '));
}

function runAttack() {
    Java.perform(function () {
        var StringCls;
        try {
            StringCls = Java.use('java.lang.String');
        } catch (e) {
            console.error('[F18-frida-java] Java.use(java.lang.String) failed: ' + e);
            return;
        }

        // Pre-warm ALL native scan bridges before tampering;
        // once `String.length` is hooked, calling Java methods
        // can recurse infinitely through Frida's bridge.
        var NativeBridge = Java.use('io.ssemaj.deviceintelligence.internal.NativeBridge');
        var nb = Java.cast(NativeBridge.INSTANCE.value, NativeBridge);
        nb.artIntegrityScan();
        nb.artIntegrityJniEnvScan();
        nb.artIntegrityInlinePrologueScan();
        nb.artIntegrityJniEntryScan();
        nb.artIntegrityAccessFlagsScan();

        var originalImpl = StringCls.length.implementation;

        console.log('[F18-frida-java] installing cls.length.implementation = function () { return 7; }');
        StringCls.length.implementation = function () {
            // Constant return value — keeps the hook ABSOLUTELY
            // self-contained. We never call back into Frida's JS
            // engine, never re-invoke String.length, never need
            // anything from `this` beyond the receiver pointer.
            return 7;
        };

        // The hook is installed. The ArtMethod for String.length
        // now has:
        //   - access_flags_ |= ACC_NATIVE         (Vector F catches flip)
        //   - entry_point_from_jni_ = bridge      (Vector E catches drift)
        // We can't call DI.collect() here because that uses
        // String.length() in dozens of places. Instead, fire the
        // two native scans directly — they don't allocate or
        // touch String objects.
        var aRecords, eRecords, fRecords;
        try {
            // Fire all five vector scans inside the tamper window.
            // The two non-method-table scans (Vector C + D) are
            // unaffected by a Java.use hook, so we skip them here.
            aRecords = nb.artIntegrityScan();
            eRecords = nb.artIntegrityJniEntryScan();
            fRecords = nb.artIntegrityAccessFlagsScan();
        } finally {
            StringCls.length.implementation = originalImpl;
            console.log('[F18-frida-java] hook removed');
        }

        // Process records OFF the hot path now that String.length
        // is back to normal.
        var aCols = ['short_id', 'live_hex', 'snap_hex',
                     'live_class', 'snap_class', 'readable',
                     'drifted'];
        var eCols = ['short_id', 'live_hex', 'snap_hex',
                     'live_class', 'snap_class', 'readable',
                     'drifted', 'is_native_by_spec'];
        var fCols = ['short_id', 'live_flags', 'snap_flags',
                     'readable', 'flip_on', 'flip_off', 'any_drift'];

        function inspect(label, records, cols) {
            console.log('[F18-frida-java] inspecting ' + label + ' records:');
            var matched = false;
            for (var i = 0; i < records.length; i++) {
                var rec = records[i];
                if (rec.indexOf('java.lang.String#length') !== 0) continue;
                matched = true;
                describeRecord('record', cols, rec.split('|'));
            }
            if (!matched) {
                console.log('[F18-frida-java]   (no record for java.lang.String#length)');
            }
        }
        inspect('Vector A (entry_point_from_quick_compiled_code_)', aRecords, aCols);
        inspect('Vector E (entry_point_from_jni_)', eRecords, eCols);
        inspect('Vector F (access_flags_)', fRecords, fCols);
    });
}

f18Prepare('F18-frida-java');
console.log('[F18-frida-java] dry-run verify (warms bridge caches and confirms 0 findings on clean state)...');
f18VerifyAndReport('F18-frida-java dry-run');

runAttack();
