/*
 * F18 Vector C — JNIEnv function-table tamper.
 *
 * Walks the current thread's JNIEnv to find the shared
 * JNINativeInterface struct (`gJniInvokeInterface` in ART) and
 * overwrites the `GetMethodID` slot with a pointer to a Frida-
 * allocated trampoline. F18's Vector C scan diffs the live
 * pointer against the JNI_OnLoad snapshot and emits
 * `jni_env_table_drifted` (HIGH). The replacement points into
 * a Frida `Memory.alloc` page (outside libart), so
 * `jni_env_table_out_of_range` (HIGH) typically also fires.
 *
 * Note: this is the canonical Frida-Java JNI hijack pattern.
 * Some Frida-Java builds tamper with the table automatically
 * the moment `Java.perform` runs; this script makes the tamper
 * explicit so the test is deterministic across Frida versions.
 *
 * Usage (one-shot, prints F18 findings before exiting):
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-c.js
 *
 * Expected output: at least one finding with
 *   kind=jni_env_table_drifted, severity=HIGH,
 *   details.function=GetMethodID
 * (usually plus `jni_env_table_out_of_range` since the trampoline
 *  lives in a Frida-allocated page)
 */

'use strict';

// Offset of `GetMethodID` inside `JNINativeInterface`. Per the
// JNI spec, indices 0..3 are reserved padding and the function
// table starts at index 4. `GetMethodID` is index 33 (the
// 34th entry counting reserved slots). One pointer per slot.
var GET_METHOD_ID_INDEX = 33;
var POINTER_SIZE = Process.pointerSize;

function findCurrentJNIEnv() {
    // Frida exposes the per-thread JNIEnv via Java.vm.tryGetEnv().
    // Falls back to attaching the current thread if unattached.
    var env = Java.vm.tryGetEnv();
    if (env) return env;
    return Java.vm.getEnv();
}

function tamperGetMethodID() {
    var env = findCurrentJNIEnv();
    if (!env || env.handle.isNull()) {
        console.error('[F18-vector-C] could not obtain JNIEnv');
        return;
    }
    // env.handle points at the JNIEnv struct, whose first
    // pointer is `functions` -> JNINativeInterface*.
    var functionsPtr = env.handle.readPointer();
    var slot = functionsPtr.add(GET_METHOD_ID_INDEX * POINTER_SIZE);
    var original = slot.readPointer();
    console.log('[F18-vector-C] JNIEnv->functions = ' + functionsPtr);
    console.log('[F18-vector-C] original GetMethodID = ' + original);

    // Allocate an executable trampoline page inside Frida's
    // arena. We don't need to actually intercept calls — F18
    // only checks the pointer value, not whether it dispatches
    // correctly. A bare `ret` (arm64: 0xd65f03c0) is enough.
    var trampoline = Memory.alloc(Process.pageSize);
    Memory.protect(trampoline, Process.pageSize, 'rwx');
    if (Process.arch === 'arm64') {
        // 0xd65f03c0 = ret
        trampoline.writeU32(0xd65f03c0);
    } else if (Process.arch === 'x64') {
        // 0xc3 = ret
        trampoline.writeU8(0xc3);
    } else {
        console.error('[F18-vector-C] unsupported arch ' + Process.arch);
        return;
    }

    // The JNINativeInterface table lives in libart's read-only
    // section, so the slot has to be temporarily writable
    // before overwriting.
    Memory.protect(slot, POINTER_SIZE, 'rw-');
    slot.writePointer(trampoline);
    Memory.protect(slot, POINTER_SIZE, 'r--');
    console.log('[F18-vector-C] swapped GetMethodID -> ' + trampoline);
}

// IMPORTANT: Frida's own Java bridge calls GetMethodID under the
// hood every time it resolves a Java method or field. If we tamper
// with GetMethodID before the bridge has cached every method ID
// the verify path needs (DeviceIntelligence.collect, the result
// TelemetryReport's accessors, every Iterator/Map$Entry it
// touches transitively), the bridge crashes mid-call.
//
// Workaround: run the full verify path ONCE before tampering.
// This forces the bridge to GetMethodID-and-cache every reference
// it'll need. The first run reports zero findings (clean snapshot,
// no hook yet); the second run AFTER tamper reports the drift.
console.log('[F18-vector-C] dry-run verify (warms bridge caches)...');
f18VerifyAndReport('F18-vector-C dry-run');

Java.perform(tamperGetMethodID);

f18VerifyAndReport('F18-vector-C');
