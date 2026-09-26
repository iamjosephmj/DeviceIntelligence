import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultPolicy, Policy } from "../src/policy.js";
import { SignalRegistry } from "../src/registry.js";
import { resolve } from "../src/signals.js";
import { definitiveHooks } from "../src/models.js";

const REG = SignalRegistry.bundled();
const POL = defaultPolicy();

test("resolves enrichment attributes", () => {
  const doc = JSON.parse('{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected '
    + 'native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so '
    + 'module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}');
  const sig = resolve(doc, REG, POL)[0];
  assert.equal(sig.moduleId, "evilmod");
  assert.deepEqual(sig.linkedLibraries, ["liblog.so", "libc.so"]);
  assert.equal(sig.linksHookLib, "libdobby.so");
  assert.equal(sig.path, "/data/adb/modules/evilmod/zygisk/arm64-v8a.so");
});

test("resolves got hijack symbol attributes", () => {
  const doc = JSON.parse('{"signals":[{"id":"INTEL_0031","severity":"CRITICAL","detail":"hooked '
    + 'function pointer. lib=/system/lib64/libbinder.so hooked_symbol=ioctl '
    + 'hooked_by=evilmod"}]}');
  const sig = resolve(doc, REG, POL)[0];
  assert.equal(sig.hookedSymbol, "ioctl");
  assert.equal(sig.hookedBy, "evilmod");
});

test("correlates definitive hook structural plus behavioral", () => {
  const doc = JSON.parse('{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline '
    + 'hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059",'
    + '"severity":"HIGH","detail":"lie. hooked_symbol=faccessat '
    + 'path=/system/bin/sh"},{"id":"INTEL_0003","severity":"CRITICAL",'
    + '"detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}');
  assert.deepEqual(definitiveHooks(resolve(doc, REG, POL)), ["faccessat"]);
});

test("unknown signal falls back to question marks", () => {
  const doc = JSON.parse('{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}');
  const sig = resolve(doc, REG, POL)[0];
  assert.equal(sig.detector, "?");
  assert.equal(sig.kind, "?");
  assert.equal(sig.severity, "CRITICAL");
});

test("legacy sig prefix bridges to intel", () => {
  const doc = JSON.parse('{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}');
  assert.equal(resolve(doc, REG, POL)[0].id, "INTEL_0052");
});
