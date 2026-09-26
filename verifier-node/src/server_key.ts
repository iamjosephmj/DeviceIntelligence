// Loads the backend X25519 private half (ServerKey.kt port). A truncated
// tail-32 fallback mirrors the Kotlin no-XDH path for exotic encodings.
import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { KeyObject } from "node:crypto";

const RAW_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

export function fromPkcs8(der: Buffer): KeyObject {
  try {
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch {
    if (der.length < 32)
      throw new Error(`PKCS#8 X25519 key too short: ${der.length} bytes`);
    return createPrivateKey({
      key: Buffer.concat([RAW_PKCS8_PREFIX, der.subarray(der.length - 32)]),
      format: "der", type: "pkcs8" });
  }
}

export function fromPem(pem: string): KeyObject {
  const cleaned = pem
    .replace(/-----BEGIN [^-]*-----/g, "")
    .replace(/-----END [^-]*-----/g, "");
  return fromPkcs8(Buffer.from(cleaned.replace(/\s+/g, ""), "base64"));
}

export function fromBytes(data: Buffer): KeyObject {
  const text = data.toString("ascii");
  return text.includes("-----BEGIN") ? fromPem(text) : fromPkcs8(data);
}

export function fromFile(path: string): KeyObject {
  return fromBytes(readFileSync(path));
}
