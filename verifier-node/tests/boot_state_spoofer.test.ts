import { test } from "node:test";
import assert from "node:assert/strict";
import { bootStateSpoofer } from "../src/scan/scan_verifier.js";
import { AttestationFields } from "../src/model.js";

const att = (boot: number | null, locked: boolean | null): AttestationFields =>
  ({ securityLevel: 2, verifiedBootState: boot, deviceLocked: locked });

test("flags spoofer props clean attestation dirty", () => {
  const reported = { vbs: "green", blocked: "1", vbmeta: "locked" };
  assert.equal(bootStateSpoofer(reported, att(2, false)), true);
});

test("flags spoofer via locked props without green", () => {
  const reported = { vbs: "", blocked: "1", vbmeta: "locked" };
  assert.equal(bootStateSpoofer(reported, att(2, false)), true);
});

test("flags spoofer via vbmeta only", () => {
  const reported = { vbs: "green", blocked: "", vbmeta: "locked" };
  assert.equal(bootStateSpoofer(reported, att(3, false)), true);
});

test("passes genuine locked device", () => {
  const reported = { vbs: "green", blocked: "1", vbmeta: "locked" };
  assert.equal(bootStateSpoofer(reported, att(0, true)), false);
});

test("does not flag plain unlocked device", () => {
  const reported = { vbs: "orange", blocked: "0", vbmeta: "unlocked" };
  assert.equal(bootStateSpoofer(reported, att(2, false)), false);
});

test("no self report is not flagged", () => {
  assert.equal(bootStateSpoofer({}, att(0, true)), false);
  assert.equal(bootStateSpoofer({}, att(2, false)), false);
});

test("clean claim with no attestation is flagged", () => {
  assert.equal(bootStateSpoofer({ vbs: "green", blocked: "1" }, null), true);
});
