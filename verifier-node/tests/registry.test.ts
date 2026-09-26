import { test } from "node:test";
import assert from "node:assert/strict";
import { SignalRegistry } from "../src/policy/registry.js";

const REG = SignalRegistry.bundled();

test("bundled registry loads the active rows", () => {
  assert.equal(REG.size, 61);
});

test("resolves a code to its meaning", () => {
  const meta = REG.get("INTEL_0042")!;
  assert.equal(meta.detector, "native_integrity");
  assert.equal(meta.kind, "text_integrity_divergence");
  assert.equal(meta.severity, "CRITICAL");
});

test("retired codes are absent", () => {
  assert.equal(REG.get("INTEL_0020"), null);   // keybox_injection, retired
  assert.equal(REG.get("INTEL_0039"), null);   // strongbox_downgrade_suspected, retired
});

test("unknown codes resolve to question marks", () => {
  const row = SignalRegistry.fromJson('{"signals":[{"id":"INTEL_9999"}]}').get("INTEL_9999")!;
  assert.equal(row.detector, "?");
  assert.equal(row.kind, "?");
});

test("null safe get", () => {
  assert.equal(REG.get(null), null);
});
