import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decode, encode } from "../src/codec.js";
import { Assurance, ScanSession } from "../src/models.js";

// Compiled to dist/tests; the canonical shared fixtures live in verifiers/fixtures.
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)),
    "..", "..", "..", "verifiers", "fixtures");

const fullSession = (): ScanSession => ({
  attestedKey: "3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
  attestedApp: { packageNames: ["com.example.app", "com.example.other"],
                 signatureDigests: ["aa".repeat(32), "bb".repeat(32)] },
  assurance: Assurance.STRONGBOX, bootState: "Verified", deviceLocked: true,
  chainTrusted: true, keyboxRevoked: false, crossLevelReuse: false,
  devicePropMismatch: false, bootStateSpoofer: false, strongboxChainMissing: false,
  softwareAttested: false, osPatchLevel: 202604, vendorPatchLevel: 20260405,
  bootPatchLevel: 20260405,
  fingerprint: { id: "cc".repeat(32), aid: "dd".repeat(32), securityLevel: "L1",
    build: "google/raven/raven:16/BP41.250:user/release-keys",
    kernel: "6.1.145-android14-11", patch: "2026-04-05", installer: "com.android.vending" },
});

test("a full session round trips field for field", () => {
  assert.deepEqual(decode(encode(fullSession())), fullSession());
});

test("the compromised flags round trip", () => {
  const bad: ScanSession = {
    attestedKey: "00", attestedApp: null, assurance: Assurance.SOFTWARE,
    bootState: "Unverified", deviceLocked: false, chainTrusted: false,
    keyboxRevoked: true, crossLevelReuse: true, devicePropMismatch: true,
    bootStateSpoofer: true, strongboxChainMissing: true, softwareAttested: true,
    osPatchLevel: null, vendorPatchLevel: null, bootPatchLevel: null, fingerprint: null,
  };
  assert.deepEqual(decode(encode(bad)), bad);
});

test("the nullable fields round trip as null", () => {
  const sparse: ScanSession = {
    attestedKey: "00", attestedApp: null, assurance: Assurance.TEE,
    bootState: "Verified", deviceLocked: true, chainTrusted: true,
    keyboxRevoked: false, crossLevelReuse: false, devicePropMismatch: false,
    bootStateSpoofer: false, strongboxChainMissing: false, softwareAttested: false,
    osPatchLevel: null, vendorPatchLevel: null, bootPatchLevel: null, fingerprint: null,
  };
  assert.deepEqual(decode(encode(sparse)), sparse);
});

test("strings needing escapes survive", () => {
  const odd: ScanSession = {
    attestedKey: "00", attestedApp: null, assurance: Assurance.TEE,
    bootState: "Verified", deviceLocked: true, chainTrusted: true,
    keyboxRevoked: false, crossLevelReuse: false, devicePropMismatch: false,
    bootStateSpoofer: false, strongboxChainMissing: false, softwareAttested: false,
    osPatchLevel: null, vendorPatchLevel: null, bootPatchLevel: null,
    fingerprint: { id: null, aid: null, securityLevel: null, build: 'a"quote\\and/slash',
                   kernel: null, patch: null, installer: null },
  };
  assert.deepEqual(decode(encode(odd)), odd);
});

test("a session from the python backend shape decodes", () => {
  const s = decode(readFileSync(join(FIXTURES, "py-session.json"), "utf8"));
  assert.equal(s.assurance, Assurance.STRONGBOX);
  assert.equal(s.bootState, "SelfSigned");
  assert.equal(s.bootStateSpoofer, true);
  assert.equal(s.deviceLocked, true);
  assert.equal(s.chainTrusted, true);
  assert.equal(s.keyboxRevoked, false);
  assert.equal(s.crossLevelReuse, false);
  assert.equal(s.devicePropMismatch, false);
  assert.equal(s.softwareAttested, false);
  assert.equal(s.osPatchLevel, 202604);
  assert.equal(s.vendorPatchLevel, 20260405);
  assert.equal(s.bootPatchLevel, 20260405);
  assert.deepEqual(s.attestedApp?.packageNames, ["tech.thessemaj.deviceintelligence.sample"]);
  assert.equal(s.fingerprint?.securityLevel, "L1");
  assert.ok(s.fingerprint!.build!.startsWith("google/raven/raven:16"));
  assert.equal(s.fingerprint?.installer, null);
});

test("a malformed document is rejected rather than half decoded", () => {
  assert.throws(() => decode('{"assurance":"TEE"}'), Error);
});
