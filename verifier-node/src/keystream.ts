// v1 symmetric token crypto (Keystream.kt port). Confidentiality in transit only.
import { createHash } from "node:crypto";

const PHRASE = "intel-verdict-token-key-v1"; // WIRE-CONSTANT (do NOT rebrand)

export function decryptBytes(cipher: Buffer): Buffer {
  const key = createHash("sha256").update(PHRASE, "utf8").digest();
  const out = Buffer.alloc(cipher.length);
  let off = 0, block = 0;
  while (off < cipher.length) {
    const blk = Buffer.alloc(4);
    blk.writeUInt32LE(block);
    const ks = createHash("sha256").update(key).update(blk).digest();
    for (let i = 0; i < Math.min(32, cipher.length - off); i++)
      out[off + i] = cipher[off + i] ^ ks[i];
    off += 32; block += 1;
  }
  return out;
}

export function decryptHex(tokenHex: string): string {
  return decryptBytes(Buffer.from(tokenHex.trim(), "hex")).toString("utf8");
}
