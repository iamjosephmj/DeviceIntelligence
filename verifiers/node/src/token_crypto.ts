// v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 discriminator.
import { createDecipheriv, createHash, diffieHellman, generateKeyPairSync, createPublicKey } from "node:crypto";
import { hkdf } from "./hkdf.js";

const PREFIX = "2:";
const INFO_PREFIX = Buffer.from("intel-token-v2", "utf8");
const HEADER = 1 + 1 + 32 + 12;
const TAG = 16;

const SPKI_X25519_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);

export function isV2(token: string): boolean {
  return token.startsWith(PREFIX);
}

function x25519PrivateFromRaw(scalar: Buffer) {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), scalar]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function x25519PublicFromRawLe(rawLe: Buffer) {
  const u = Buffer.from(rawLe);
  u[31] &= 0x7f; // RFC 7748: the ignored high bit
  return createPublicKey({
    key: Buffer.concat([SPKI_X25519_PREFIX, u]), format: "der", type: "spki",
  });
}

export function decryptV2(tokenV2: string, serverScalar: Buffer): Buffer {
  if (!tokenV2.startsWith(PREFIX)) throw new Error("not a v2 token");
  const body = tokenV2.slice(PREFIX.length);
  if (body.length % 2 !== 0) throw new Error("odd-length hex");
  let p: Buffer;
  try { p = Buffer.from(body, "hex"); } catch { throw new Error("bad hex char"); }
  if (p.length < HEADER + TAG) throw new Error("v2 token too short");

  const version = p[0], epoch = p[1];
  const ephPub = p.subarray(2, 34), nonce = p.subarray(34, 46);
  const ctAndTag = p.subarray(HEADER);

  const eph = Buffer.from(ephPub);
  eph[31] &= 0x7f;
  const shared = diffieHellman({
    privateKey: x25519PrivateFromRaw(serverScalar),
    publicKey: x25519PublicFromRawLe(eph),
  });
  const key = hkdf(shared, nonce, Buffer.concat([INFO_PREFIX, Buffer.of(epoch)]), 32);

  const aad = Buffer.concat([Buffer.of(version, epoch), ephPub]);
  const ct = ctAndTag.subarray(0, ctAndTag.length - TAG);
  const tag = ctAndTag.subarray(ctAndTag.length - TAG);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export { generateKeyPairSync, createHash };
