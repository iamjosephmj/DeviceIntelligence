// RFC 7748 known-answer tests — via node:crypto's X25519.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";

const V1_K = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
const V1_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
const V1_O = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
const V2_K = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
const V2_U = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
const V2_O = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
const DH_A = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const DH_B = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

const PRIV_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                                 0x6e, 0x03, 0x21, 0x00]);

function priv(h: string) {
  return createPrivateKey({ key: Buffer.concat([PRIV_PREFIX, Buffer.from(h, "hex")]),
                            format: "der", type: "pkcs8" });
}
function pub(h: string) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(h, "hex")]),
                           format: "der", type: "spki" });
}
function mult(kh: string, uh: string): string {
  return diffieHellman({ privateKey: priv(kh), publicKey: pub(uh) }).toString("hex");
}

test("rfc7748 vector1", () => {
  assert.equal(mult(V1_K, V1_U), V1_O);
});

test("rfc7748 vector2", () => {
  assert.equal(mult(V2_K, V2_U), V2_O);
});

test("diffie hellman agrees", () => {
  const aPub = createPublicKey(priv(DH_A)).export({ format: "der", type: "spki" })
    .subarray(SPKI_PREFIX.length).toString("hex");
  const bPub = createPublicKey(priv(DH_B)).export({ format: "der", type: "spki" })
    .subarray(SPKI_PREFIX.length).toString("hex");
  assert.equal(aPub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  assert.equal(bPub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  assert.equal(mult(DH_A, bPub), SHARED);
  assert.equal(mult(DH_B, aPub), SHARED);
});
