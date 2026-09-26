import { createHash, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { X509Certificate } from "node:crypto";

export function parseChain(certsHex: string[]): X509Certificate[] {
  return certsHex.map(h => new X509Certificate(Buffer.from(h, "hex")));
}

function sha256Fp(cert: X509Certificate): Buffer {
  return createHash("sha256").update(cert.raw).digest();
}

export function verifyToPinnedRoot(chain: X509Certificate[], pinnedRoots: X509Certificate[]): X509Certificate {
  if (!chain.length) throw new Error("empty chain");
  for (let i = 0; i < chain.length - 1; i++) verifySignedBy(chain[i], chain[i + 1]);
  const top = chain[chain.length - 1];
  const topFp = sha256Fp(top);
  for (const root of pinnedRoots) {
    if (topFp.equals(sha256Fp(root))) return root;
    try { verifySignedBy(top, root); return root; } catch { /* try next */ }
  }
  throw new Error("chain top does not chain to a pinned Google root");
}

function verifySignedBy(cert: X509Certificate, issuer: X509Certificate): void {
  if (!cert.verify(issuer.publicKey)) throw new Error("signature mismatch");
}
