// Offline parity against a REAL token captured from the rooted Pixel 6 Pro
// (KernelSU + TrickyStore). The Node verifier must grade this exact token+nonce
// COMPROMISED, identically to the Kotlin reference (and the Python port).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TokenVerifier } from "../src/token_verifier.js";

// Compiled to dist/tests; the canonical shared fixtures live in verifiers/fixtures.
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)),
    "..", "..", "..", "verifiers", "fixtures");

test("pixel real token parity compromised", () => {
  const token = readFileSync(join(FIXTURES, "pixel-token.hex"), "utf8").trim();
  const nonce = readFileSync(join(FIXTURES, "pixel-nonce.hex"), "utf8").trim();
  const res = new TokenVerifier().verify(token, nonce);

  assert.equal(res.authentic, true);
  assert.equal(res.deviceIntegrityOk, false);
  assert.equal(res.decision, "COMPROMISED");

  // The token is a registryVersion-1 capture: its attestation signal carries the
  // pre-reshuffle code, which the v2 table resolves to whatever row owns that
  // number today. A fresh device capture re-establishes end-to-end attribution.
  const sig0 = res.signals.find(s => s.id === "INTEL_0000");
  assert.ok(sig0 !== undefined, "INTEL_0000 signal present");
  assert.equal(sig0.blocking, true);

  const checks = Object.fromEntries(res.checks.map(c => [c.name, c.ok]));
  assert.equal(checks["binding present"], true);
  assert.equal(checks["nonce matches issued"], true);
  assert.equal(checks["chain -> pinned Google root"], true);
  assert.equal(checks["signature over verdict"], true);
  assert.equal(checks["verified boot state = Verified"], false);
});
