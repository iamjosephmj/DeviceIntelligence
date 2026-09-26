import { readFileSync } from "node:fs";

function normalize(serialHex: string): string {
  const s = serialHex.trim().toLowerCase().replace(/^0x/, "").replace(/^0+/, "");
  return s || "0";
}

export class AttestationCrl {
  constructor(private revoked: Set<string>) {}
  isRevoked(cert: X509Certificate): boolean {
    return this._revoked.has(normalize(cert.serialNumber.toString(16)));
  }
  firstRevoked(...chains: X509Certificate[][]): string | null {
    for (const chain of chains) for (const cert of chain) {
      const h = normalize(cert.serialNumber.toString(16));
      if (this._revoked.has(h)) return h;
    }
    return null;
  }
  get size(): number { return this._revoked.size; }
  static parse(text: string): AttestationCrl {
    const set = new Set<string>();
    for (const line of text.split("\n")) {
      const s = normalize(line.split("#")[0].trim());
      if (s) set.add(s);
    }
    return new AttestationCrl(set);
  }
  static fromFile(p: string): AttestationCrl {
    return AttestationCrl.parse(readFileSync(p, "utf8"));
  }
}
