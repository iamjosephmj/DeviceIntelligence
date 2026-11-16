import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TokenDecoder } from "../src/tokens/token_decoder.js";
import { defaultPolicy } from "../src/policy/policy.js";
import { SignalRegistry } from "../src/policy/registry.js";
import { resolve as resolveSignals, device as deviceOf } from "../src/tokens/signals.js";

// Compiled to dist/tests; the canonical shared fixtures live in verifiers/fixtures.
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)),
    "..", "..", "..", "verifiers", "fixtures");
const REG = SignalRegistry.bundled();
const POL = defaultPolicy();

test("decodes real challenge token fixture", () => {
  const d = new TokenDecoder().decode(
    readFileSync(join(FIXTURES, "pixel-challenge.token"), "utf8").trim(), REG, POL);
  assert.equal(d.schemaVersion, 3);
  assert.equal(d.hasBinding, true);
});

test("resolve maps known signal from registry", () => {
  const doc = { signals: [{ id: "INTEL_0052", detail: "x" }] };
  const out = resolveSignals(doc, REG, POL);
  assert.equal(out[0].id, "INTEL_0052");
  assert.notEqual(out[0].detector, "?");
  assert.equal(out[0].detail, "x");
});

test("resolve falls back for unknown signal", () => {
  const doc = { signals: [{ id: "INTEL_9999", severity: "CRITICAL" }] };
  const out = resolveSignals(doc, REG, POL);
  assert.equal(out[0].id, "INTEL_9999");
  assert.equal(out[0].detector, "?");
  assert.equal(out[0].severity, "CRITICAL");
});

test("device parses when present and null when absent", () => {
  const d = deviceOf({ device: { api: 34, abi: "arm64-v8a", model: "Pixel" } });
  assert.equal(d.api, 34);
  assert.equal(d.abi, "arm64-v8a");
  assert.equal(d.model, "Pixel");
  assert.equal(deviceOf({}), null);
});
