import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_MAX_AGE_SECONDS, SessionSigner } from "../src/session_signer.js";
import { Assurance, Session } from "../src/models.js";

// Fixed lab HMAC key for stateless session tokens — shared by every port.
const SERVER_KEY = Buffer.from("intel-lab-session-key-v1", "utf8");
const ISSUED_AT = 1_787_220_000;
const SESSION: Session = {
  pinnedKeySpkiHex: "30591301deadbeef", assurance: Assurance.STRONGBOX,
  bootState: "Verified", deviceLocked: true, issuedAt: ISSUED_AT,
  chainTrusted: false, keyboxRevoked: false, crossLevelReuse: false,
  strongboxChainMissing: false, devicePropMismatch: false,
  bootStateSpoofer: false, softwareAttested: false,
};

test("round trips", () => {
  const signer = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  assert.deepEqual(signer.open(signer.issue(SESSION)), SESSION);
});

test("rejects expired", () => {
  const signer = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT);
  const late = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS,
                                 () => ISSUED_AT + DEFAULT_MAX_AGE_SECONDS + 1);
  assert.equal(late.open(signer.issue(SESSION)), null);
});

test("rejects zero timestamp", () => {
  const stampless: Session = { ...SESSION, issuedAt: 0 };
  const zero = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => 0);
  const opener = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  assert.equal(opener.open(zero.issue(stampless)), null);
});

test("rejects tampered payload", () => {
  const signer = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  const sessionId = signer.issue(SESSION);
  const [payload, mac] = sessionId.split(".", 2);
  const forged = payload.slice(0, -1) + (payload.endsWith("A") ? "B" : "A") + "." + mac;
  assert.equal(signer.open(forged), null);
});

test("rejects wrong key", () => {
  const signer = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  const forgedSigner = new SessionSigner(Buffer.from("different-key", "utf8"),
                                         DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  assert.equal(forgedSigner.open(signer.issue(SESSION)), null);
});

test("rejects malformed", () => {
  const signer = new SessionSigner(SERVER_KEY, DEFAULT_MAX_AGE_SECONDS, () => ISSUED_AT + 100);
  assert.equal(signer.open("not-a-session"), null);
});
