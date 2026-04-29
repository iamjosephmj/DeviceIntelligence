/*
 * F18 Vector D — inline trampoline on art::ArtMethod::Invoke.
 *
 * Uses Frida `Interceptor.attach` to install a hook on
 * `_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc`
 * (a.k.a. `art::ArtMethod::Invoke`). Frida patches the first
 * ~16 bytes of the function with a branch to its own
 * trampoline. F18's Vector D scan re-reads those bytes on the
 * next evaluate and emits `art_internal_prologue_drifted`
 * (HIGH).
 *
 * If the script attaches BEFORE the sample app launches (e.g.
 * via `frida -U -f io.ssemaj.sample -l ...`), the snapshot
 * captured at JNI_OnLoad already reflects the patch, so the
 * drift signal won't fire — but the embedded API-keyed
 * baseline check WILL flag it as
 * `art_internal_prologue_baseline_mismatch` (MEDIUM) instead.
 *
 * Usage (one-shot, prints F18 findings before exiting):
 *   frida -U -n io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-d.js
 *
 * Expected output: at least one finding with
 *   kind=art_internal_prologue_drifted, severity=HIGH,
 *   details.symbol=_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc
 *
 * Pre-launch variant (exercises `baseline_mismatch` instead of
 * `_drifted`):
 *   frida -U -f io.ssemaj.sample \
 *     -l tools/red-team/_verify_helper.js \
 *     -l tools/red-team/frida-vector-d.js
 */

'use strict';

var TARGET = '_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc';

// Find the symbol via libart's dynsym. `dlsym` is blocked by
// the Android linker namespace for app processes, so we use
// Frida's Module API which walks the in-memory ELF directly.
function resolveTarget() {
    var libart = Process.findModuleByName('libart.so');
    if (!libart) {
        console.error('[F18-vector-D] libart.so not loaded?');
        return null;
    }
    var sym = libart.findExportByName(TARGET);
    if (!sym) {
        console.error('[F18-vector-D] could not resolve ' + TARGET);
        console.error('[F18-vector-D] libart base = ' + libart.base);
        return null;
    }
    return sym;
}

function installHook() {
    var addr = resolveTarget();
    if (!addr) return;
    console.log('[F18-vector-D] hooking ' + TARGET + ' @ ' + addr);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // Frida has already patched the prologue at this
            // point — the onEnter body itself is decorative,
            // we just need the byte-rewrite to have happened.
        },
    });
    Interceptor.flush();
    console.log('[F18-vector-D] inline trampoline installed');
}

installHook();

f18VerifyAndReport('F18-vector-D');
