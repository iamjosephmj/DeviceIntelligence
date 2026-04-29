/*
 * F18 Vector A — direct ArtMethod entry-point overwrite (the
 * canonical Xposed-family attack).
 *
 * Resolves the `ArtMethod*` for `java.lang.Object#<init>` via the
 * standard JNI `FindClass` + `GetMethodID` calls, then overwrites
 * the `entry_point_from_quick_compiled_code_` field (offset 0x18
 * on Android API 33+, 0x20 on API 28-32) with a pointer to a
 * Frida-allocated trampoline. This is exactly what Xposed,
 * EdXposed, LSPosed, YAHFA, Pine, SandHook and Whale all do under
 * the hood.
 *
 * F18's Vector A scan re-reads the entry pointer and emits BOTH
 * `art_method_entry_drifted` (HIGH — snapshot was libart, live
 * differs to a non-libart region) AND
 * `art_method_entry_out_of_range` (HIGH — Frida's mmap'd page
 * isn't classified as libart / boot OAT / JIT cache).
 *
 * About target choice: `Object.<init>` is picked because (1) it's
 * in F18's frozen-method registry, (2) its ArtMethod is encoded
 * as a direct pointer (so we can write to it without going through
 * ART's JNI ID indexing), and (3) its entry-point snapshot lands
 * in libart's RX segment (a stable "before" value), so a redirect
 * to anonymous memory produces an unambiguous drift signal.
 *
 * About `Object.hashCode` (the previous target via Java.use):
 * Frida-Java's `cls.method.implementation = ...` does NOT modify
 * `entry_point_from_quick_compiled_code_` — it patches a different
 * ART internal (`entry_point_from_jni_` plus a method-flag flip).
 * So Java.use-style hooks are invisible to Vector A by design.
 * Vector A's threat model is Xposed-family direct ArtMethod
 * tampering; that's what this script exercises.
 *
 * Tamper window: because we're patching `Object.<init>`, every
 * Java object allocation between the overwrite and the restore
 * goes through the trampoline and crashes. We therefore keep the
 * window microseconds wide — patch, fire one direct native scan
 * (which does its work in C++ and does NOT call user-level
 * `Object.<init>`), restore, then translate the scan records into
 * Findings off the hot path.
 *
 * Usage (one-shot, prints F18 findings before exiting):
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-a.js
 *
 * Expected output:
 *   art_method_entry_drifted (HIGH) on Object#<init>
 *   art_method_entry_out_of_range (HIGH) on Object#<init>
 */

'use strict';

var FIND_CLASS_INDEX     = 6;
var GET_METHOD_ID_INDEX  = 33;

// Mirror of `deviceintelligence/src/main/cpp/dicore/art_integrity/offsets.cpp`.
function entryOffsetForApi(api) {
    if (api < 28) return null;
    if (api <= 32) return 0x20;
    return 0x18;
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
    var ctorName = Memory.allocUtf8String('<init>');
    var ctorSig = Memory.allocUtf8String('()V');
    var clazz = FindClass(env.handle, clsName);
    if (clazz.isNull()) return null;
    var artMethod = GetMethodID(env.handle, clazz, ctorName, ctorSig);
    if (artMethod.isNull()) return null;
    return artMethod;
}

function allocTrampoline() {
    var trampoline = Memory.alloc(Process.pageSize);
    Memory.protect(trampoline, Process.pageSize, 'rwx');
    if (Process.arch === 'arm64') {
        trampoline.writeU32(0xd65f03c0); // ret
    } else if (Process.arch === 'x64') {
        trampoline.writeU8(0xc3); // ret
    } else {
        return null;
    }
    return trampoline;
}

function runAttack() {
    Java.perform(function () {
        var env = Java.vm.tryGetEnv() || Java.vm.getEnv();
        if (!env || env.handle.isNull()) {
            console.error('[F18-vector-A] could not obtain JNIEnv');
            return;
        }

        var artMethod = resolveArtMethod(env);
        if (!artMethod) {
            console.error('[F18-vector-A] could not resolve Object.<init> ArtMethod*');
            return;
        }

        var Build = Java.use('android.os.Build$VERSION');
        var api = Build.SDK_INT.value;
        var entryOffset = entryOffsetForApi(api);
        if (entryOffset === null) {
            console.error('[F18-vector-A] unsupported API ' + api);
            return;
        }

        var trampoline = allocTrampoline();
        if (!trampoline) {
            console.error('[F18-vector-A] unsupported arch ' + Process.arch);
            return;
        }

        // Pre-resolve every Java/JNI ref we'll need DURING the
        // tamper window. Once Object.<init> is patched, any new
        // Java.use() / Java.cast() / object allocation hits the
        // trampoline and crashes.
        var NativeBridge = Java.use('io.ssemaj.deviceintelligence.internal.NativeBridge');
        var nb = Java.cast(NativeBridge.INSTANCE.value, NativeBridge);
        // Warm Frida's bridge cache for artIntegrityScan().
        nb.artIntegrityScan();

        var entrySlot = artMethod.add(entryOffset);
        var original = entrySlot.readPointer();

        console.log('[F18-vector-A] target ArtMethod  = ' + artMethod);
        console.log('[F18-vector-A] entry_point @ +0x' + entryOffset.toString(16));
        console.log('[F18-vector-A] original entry    = ' + original);
        console.log('[F18-vector-A] new trampoline    = ' + trampoline);

        // === TAMPER WINDOW START ===
        // Anything that allocates a Java object here will execute
        // garbage. Keep this block to a single native call.
        entrySlot.writePointer(trampoline);
        var records = nb.artIntegrityScan();
        entrySlot.writePointer(original);
        // === TAMPER WINDOW END (safe to allocate again) ===

        console.log('[F18-vector-A] entry restored; scan captured ' +
                    records.length + ' record(s)');

        // Find the Object#<init> record and assert the expected
        // findings would have fired.
        var matched = false;
        for (var i = 0; i < records.length; i++) {
            var rec = records[i];
            if (rec.indexOf('java.lang.Object#<init>') !== 0) continue;
            matched = true;
            var parts = rec.split('|');
            // short_id|live_hex|snap_hex|live_class|snap_class|readable|drifted
            var liveHex   = parts[1];
            var snapHex   = parts[2];
            var liveClass = parts[3];
            var snapClass = parts[4];
            var drifted   = parts[6];
            console.log('[F18-vector-A] scan record   live=' + liveHex +
                        ' snap=' + snapHex +
                        ' live_class=' + liveClass +
                        ' snap_class=' + snapClass +
                        ' drifted=' + drifted);
            if (liveClass === 'unknown') {
                console.log('[F18-vector-A]   => F18 will emit art_method_entry_out_of_range (HIGH)');
            }
            if (drifted === '1' && snapClass === 'libart' && liveClass !== 'libart') {
                console.log('[F18-vector-A]   => F18 will emit art_method_entry_drifted (HIGH)');
            }
        }
        if (!matched) {
            console.error('[F18-vector-A] Object#<init> record not present in scan output?');
        }
    });
}

// Pre-resolve every Java.use binding the verify helper needs
// BEFORE we tamper. Same reasoning as Vector C — once Object.<init>
// dispatches into garbage, any Frida bridge call that constructs
// an object crashes.
f18Prepare('F18-vector-A');
console.log('[F18-vector-A] dry-run verify (warms bridge caches and confirms 0 findings on clean state)...');
f18VerifyAndReport('F18-vector-A dry-run');

runAttack();
