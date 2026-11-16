import { test } from "node:test";
import assert from "node:assert/strict";
import { Policy, defaultPolicy, isBlocking } from "../src/policy/policy.js";

const pol = (over: Partial<Policy> = {}): Policy => ({ ...defaultPolicy(), ...over });

test("critical severity blocks", () => {
  assert.equal(isBlocking(pol(), "INTEL_0001", "CRITICAL"), true);
});

test("non critical severity does not block by default", () => {
  assert.equal(isBlocking(pol(), "INTEL_0019", "HIGH"), false);
  assert.equal(isBlocking(pol(), "INTEL_0050", "MEDIUM"), false);
});

test("allow list overrides severity", () => {
  assert.equal(isBlocking(pol({ allow: new Set(["INTEL_0052"]) }), "INTEL_0052", "CRITICAL"), false);
});

test("block list overrides severity", () => {
  assert.equal(isBlocking(pol({ block: new Set(["INTEL_0050"]) }), "INTEL_0050", "MEDIUM"), true);
});

test("allow takes precedence over block", () => {
  const p = pol({ allow: new Set(["INTEL_0001"]), block: new Set(["INTEL_0001"]) });
  assert.equal(isBlocking(p, "INTEL_0001", "CRITICAL"), false);
});

test("severity comparison is case insensitive", () => {
  assert.equal(isBlocking(pol(), null, "critical"), true);
});

test("null severity does not block by default", () => {
  assert.equal(isBlocking(pol(), null, null), false);
});

test("confirmed rwx hook pool always blocks", () => {
  assert.equal(isBlocking(pol({ observeUnconfirmedRwx: true }),
    "INTEL_0052", "CRITICAL", "rwx_memory_mapping", 3), true);
});

test("bare rwx downgrades only when opted in", () => {
  assert.equal(isBlocking(pol(), "INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0), true);
  assert.equal(isBlocking(pol({ observeUnconfirmedRwx: true }),
    "INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0), false);
});
