/*
 * F18 Vector E — direct ArtMethod->entry_point_from_jni_ overwrite.
 *
 * Closes Vector A's blind spot for Frida-Java's
 * `cls.method.implementation = ...` style hooks. Frida-Java does
 * NOT touch `entry_point_from_quick_compiled_code_` (Vector A's
 * field). It writes its bridge pointer into the `data_` slot
 * (which for native methods is `entry_point_from_jni_`) and —
 * for non-native methods — also flips the `ACC_NATIVE` bit
 * (Vector F catches the bit flip).
 *
 * This script targets a NATIVE method (`Object#hashCode`) and
 * overwrites its `entry_point_from_jni_` slot with a Frida-
 * allocated trampoline. F18 Vector E should emit
 * `art_method_jni_entry_drifted` (HIGH) because the snapshot
 * captured the original libart-resident JNI bridge and the
 * live value points at unknown memory.
 *
 * About target choice: `Object#hashCode` is a JDK-native method
 * whose original `data_` snapshot lands in libart's RX segment
 * (not in boot.art), so a redirect produces the cleanest possible
 * libart→unknown drift signal. Other registry slots (e.g.
 * `Object#getClass`) work identically.
 *
 * Tamper window: hashCode is called by Java's Object.hashCode()
 * paths; redirecting it to a `ret` trampoline returning 0 is
 * harmless for our verify pass (no allocations through this
 * code path during the F18 collect call).
 *
 * Usage:
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-e.js
 *
 * Expected output:
 *   art_method_jni_entry_drifted (HIGH) on Object#hashCode
 *   (out_of_range may also fire if snapshot was libart)
 */

'use strict';

var FIND_CLASS_INDEX     = 6;
var GET_METHOD_ID_INDEX  = 33;

// Mirror of `deviceintelligence/src/main/cpp/dicore/art_integrity/offsets.cpp`.
// `data_` (entry_point_from_jni_) sits one pointer slot below
// entry_point_from_quick_compiled_code_.
function jniEntryOffsetForApi(api) {
    if (api < 28) return null;
    if (api <= 32) return 0x18;  // 0x20 - 8
    return 0x10;                 // 0x18 - 8
}

function resolveArtMethod(env) {
    var fns = env.handle.readPointer();
    var ptr = Process.pointerSize;
    var FindClass = new NativeFunction(
        fns.add(FIND_CLASS_INDEX * ptr).readPointer(),
        'pointer', ['pointer', 'pointer']);
    var GetMethodID = new NativeFunction(
        fns.add(GET_METHOD_ID_INDEX * ptr).readPointer(),
        'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    var clsName = Memory.allocUtf8String('java/lang/Object');
    var methodName = Memory.allocUtf8String('hashCode');
    var sig = Memory.allocUtf8String('()I');
    var clazz = FindClass(env.handle, clsName);
    if (clazz.isNull()) return null;
    var artMethod = GetMethodID(env.handle, clazz, methodName, sig);
    if (artMethod.isNull()) return null;
    return artMethod;
}

function allocReturnZeroTrampoline() {
    var trampoline = Memory.alloc(Process.pageSize);
    Memory.protect(trampoline, Process.pageSize, 'rwx');
    if (Process.arch === 'arm64') {
        // mov w0, #0 ; ret
        trampoline.writeU32(0x52800000);
        trampoline.add(4).writeU32(0xd65f03c0);
    } else if (Process.arch === 'x64') {
        // xor eax, eax ; ret
        trampoline.writeU8(0x31).add(1)
                  .writeU8(0xc0).add(1)
                  .writeU8(0xc3);
    } else {
        return null;
    }
    return trampoline;
}

function runAttack() {
    Java.perform(function () {
        var env = Java.vm.tryGetEnv() || Java.vm.getEnv();
        if (!env || env.handle.isNull()) {
            console.error('[F18-vector-E] could not obtain JNIEnv');
            return;
        }

        var artMethod = resolveArtMethod(env);
        if (!artMethod) {
            console.error('[F18-vector-E] could not resolve Object.hashCode ArtMethod*');
            return;
        }

        var Build = Java.use('android.os.Build$VERSION');
        var api = Build.SDK_INT.value;
        var jniOffset = jniEntryOffsetForApi(api);
        if (jniOffset === null) {
            console.error('[F18-vector-E] unsupported API ' + api);
            return;
        }

        var trampoline = allocReturnZeroTrampoline();
        if (!trampoline) {
            console.error('[F18-vector-E] unsupported arch ' + Process.arch);
            return;
        }

        var NativeBridge = Java.use('io.ssemaj.deviceintelligence.internal.NativeBridge');
        var nb = Java.cast(NativeBridge.INSTANCE.value, NativeBridge);
        // Warm the artIntegrityJniEntryScan bridge cache.
        nb.artIntegrityJniEntryScan();

        var slot = artMethod.add(jniOffset);
        var original = slot.readPointer();

        console.log('[F18-vector-E] target ArtMethod    = ' + artMethod);
        console.log('[F18-vector-E] data_/jni @ +0x' + jniOffset.toString(16));
        console.log('[F18-vector-E] original data_      = ' + original);
        console.log('[F18-vector-E] new trampoline      = ' + trampoline);

        // === TAMPER WINDOW START ===
        // Object.hashCode redirected to return 0 would break every
        // HashMap during the F18 collect path. Keep the window
        // microscopically small: write, fire one direct native
        // scan (no Java allocations), restore, then process the
        // records off the hot path.
        slot.writePointer(trampoline);
        var records = nb.artIntegrityJniEntryScan();
        slot.writePointer(original);
        // === TAMPER WINDOW END ===

        console.log('[F18-vector-E] entry restored; scan captured ' +
                    records.length + ' record(s)');

        var matched = false;
        for (var i = 0; i < records.length; i++) {
            var rec = records[i];
            if (rec.indexOf('java.lang.Object#hashCode') !== 0) continue;
            matched = true;
            var parts = rec.split('|');
            // short_id|live_hex|snap_hex|live_class|snap_class|readable|drifted|is_native_by_spec
            var liveHex = parts[1];
            var snapHex = parts[2];
            var liveClass = parts[3];
            var snapClass = parts[4];
            var readable = parts[5];
            var drifted = parts[6];
            var isNativeBySpec = parts[7];
            console.log('[F18-vector-E] scan record    live=' + liveHex +
                        ' snap=' + snapHex +
                        ' live_class=' + liveClass +
                        ' snap_class=' + snapClass +
                        ' readable=' + readable +
                        ' drifted=' + drifted +
                        ' is_native_by_spec=' + isNativeBySpec);
            if (drifted === '1' && isNativeBySpec === '1') {
                console.log('[F18-vector-E]   => F18 will emit art_method_jni_entry_drifted (HIGH)');
            }
            if (liveClass === 'unknown' &&
                (snapClass === 'libart' || snapClass === 'boot_oat')) {
                console.log('[F18-vector-E]   => F18 will emit art_method_jni_entry_out_of_range (HIGH)');
            }
        }
        if (!matched) {
            console.error('[F18-vector-E] Object#hashCode record not found in scan output?');
        }
    });
}

// Pre-warm Frida bridges before tampering. The dry-run also
// verifies a clean device shows 0 F18 findings BEFORE the hook.
f18Prepare('F18-vector-E');
console.log('[F18-vector-E] dry-run verify (warms bridge caches and confirms 0 findings on clean state)...');
f18VerifyAndReport('F18-vector-E dry-run');

runAttack();
