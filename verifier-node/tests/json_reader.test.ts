// The stdlib JSON reader satisfies the verifier's parse contract.
import { test } from "node:test";
import assert from "node:assert/strict";

test("parses a signed content shaped document", () => {
  const doc = JSON.parse('{"schemaVersion":3,"type":"challenge","ts":1787,'
    + '"signals":[{"id":"INTEL_0052","severity":"CRITICAL"}]}');
  assert.equal(doc.schemaVersion, 3);
  assert.equal(doc.signals[0].id, "INTEL_0052");
});

test("rejects trailing data", () => {
  assert.throws(() => JSON.parse('{"a":1} junk'), SyntaxError);
});
