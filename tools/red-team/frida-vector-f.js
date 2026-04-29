/*
 * F18 Vector F — direct ACC_NATIVE bit flip on a Java method.
 *
 * The most reliable Frida-Java fingerprint:
 * `cls.method.implementation = ...` flips the `ACC_NATIVE` bit
 * (0x100) in `access_flags_` ON for non-native target methods,
 * so ART's dispatcher routes the call through the JNI bridge
 * (which Frida-Java has installed in `entry_point_from_jni_`).
 * Java methods do not legitimately become native at runtime, so
 * a 0→1 transition is a binary tamper signal.
 *
 * This script targets `String#length` (non-native, ACC_NATIVE
 * unset at JNI_OnLoad) and flips the bit ON. F18 Vector F should
 * emit `art_method_acc_native_flipped_on` (HIGH).
 *
 * About target choice: `String#length` is in F18's frozen-method
 * registry, has a pointer-encoded jmethodID (so the access_flags_
 * read works), and is non-native (so the bit flip is the canonical
 * Frida-Java direction). Vector F handles both directions —
 * `Object#hashCode` (native) is a flip-OFF target; same machinery.
 *
 * Tamper window: just flipping a flag does NOT redirect any code
 * path; ART will only consult the new value on its next dispatch
 * decision. We can hold the tamper for the entire F18 verify
 * call without crashing anything.
 *
 * Usage:
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-f.js
 *
 * Expected output:
 *   art_method_acc_native_flipped_on (HIGH) on java.lang.String#length
 */

'use strict';

var FIND_CLASS_INDEX     = 6;
var GET_METHOD_ID_INDEX  = 33;
var ACC_NATIVE           = 0x00000100;
var ACCESS_FLAGS_OFFSET  = 0x04;  // stable across API 28-36

function resolveArtMethod(env) {
    var fns = env.handle.readPointer();
    var ptr = Process.pointerSize;
    var FindClass = new NativeFunction(
        fns.add(FIND_CLASS_INDEX * ptr).readPointer(),
        'pointer', ['pointer', 'pointer']);
    var GetMethodID = new NativeFunction(
        fns.add(GET_METHOD_ID_INDEX * ptr).readPointer(),
        'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    var clsName = Memory.allocUtf8String('java/lang/String');
    var methodName = Memory.allocUtf8String('length');
    var sig = Memory.allocUtf8String('()I');
    var clazz = FindClass(env.handle, clsName);
    if (clazz.isNull()) return null;
    var artMethod = GetMethodID(env.handle, clazz, methodName, sig);
    if (artMethod.isNull()) return null;
    return artMethod;
}

function runAttack() {
    Java.perform(function () {
        var env = Java.vm.tryGetEnv() || Java.vm.getEnv();
        if (!env || env.handle.isNull()) {
            console.error('[F18-vector-F] could not obtain JNIEnv');
            return;
        }

        var artMethod = resolveArtMethod(env);
        if (!artMethod) {
            console.error('[F18-vector-F] could not resolve String.length ArtMethod*');
            return;
        }

        var slot = artMethod.add(ACCESS_FLAGS_OFFSET);
        var original = slot.readU32();
        // JavaScript bitwise ops return signed 32-bit; >>> 0 forces
        // back to the unsigned representation that writeU32 expects.
        var tampered = (original | ACC_NATIVE) >>> 0;

        console.log('[F18-vector-F] target ArtMethod  = ' + artMethod);
        console.log('[F18-vector-F] access_flags @ +0x' + ACCESS_FLAGS_OFFSET.toString(16));
        console.log('[F18-vector-F] original flags    = 0x' + original.toString(16) +
                    ' (native=' + (((original & ACC_NATIVE) >>> 0) ? 1 : 0) + ')');
        console.log('[F18-vector-F] tampered flags    = 0x' + tampered.toString(16) +
                    ' (native=1)');

        // Just flipping a flag doesn't redirect code; we can
        // safely hold the tamper for the entire verify pass.
        slot.writeU32(tampered);
        try {
            f18VerifyAndReport('F18-vector-F post-attack');
        } finally {
            slot.writeU32(original);
            console.log('[F18-vector-F] flags restored');
        }
    });
}

f18Prepare('F18-vector-F');
console.log('[F18-vector-F] dry-run verify (warms bridge caches and confirms 0 findings on clean state)...');
f18VerifyAndReport('F18-vector-F dry-run');

runAttack();
