// HKDF-SHA256 (RFC 5869) via node:crypto. Empty salt -> 32 zero bytes (RFC convention).
import { hkdfSync, createHash } from "node:crypto";

export function sha256(ikm: Buffer, salt: Buffer, info: Buffer, outLen: number): Buffer {
  if (outLen < 0 || outLen > 255 * 32) throw new RangeError(`HKDF outLen out of range: ${outLen}`);
  const effSalt = salt.length ? salt : Buffer.alloc(32);
  return Buffer.from(hkdfSync("sha256", ikm, effSalt, info, outLen));
}

export function sha256Of(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}
