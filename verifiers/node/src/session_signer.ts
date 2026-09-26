import { createHmac, timingSafeEqual } from "node:crypto";
import { Assurance, Session } from "./models.js";

export const DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60;

export class SessionSigner {
  private key: Buffer;
  private maxAge: number;
  private now: () => number;
  constructor(serverKey: Buffer, maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS, now?: () => number) {
    this.key = Buffer.from(serverKey);
    this.maxAge = maxAgeSeconds;
    this.now = now ?? (() => Math.floor(Date.now() / 1000));
  }
  issue(s: Session): string {
    const payload = JSON.stringify({
      pinnedKey: s.pinnedKeySpkiHex, assurance: s.assurance, boot: s.boot_state,
      locked: s.device_locked, issuedAt: s.issued_at, chainTrusted: s.chain_trusted,
      kbRevoked: s.keybox_revoked, xlReuse: s.cross_level_reuse,
      sbMissing: s.strongbox_chain_missing, propMismatch: s.device_prop_mismatch,
      bootSpoofer: s.boot_state_spoofer, swAttest: s.software_attested,
    });
    const b64 = (b: Buffer) => b.toString("base64url");
    return `${b64(Buffer.from(payload))}.${b64(this._mac(Buffer.from(payload)))}`;
  }
  open(sessionId: string): Session | null {
    try {
      const dot = sessionId.indexOf(".");
      if (dot < 0) return null;
      const b64d = (s: string) => Buffer.from(s, "base64url");
      const payload = b64d(sessionId.slice(0, dot));
      const got = b64d(sessionId.slice(dot + 1));
      if (!this._mac(payload).equals(got)) return null;
      const o = JSON.parse(payload.toString("utf8"));
      const issuedAt = o.issuedAt;
      if (typeof issuedAt !== "number" || issuedAt <= 0 || this.now() - issuedAt > this.maxAge)
        return null;
      return {
        pinnedKeySpkiHex: o.pinnedKey, assurance: Assurance[o.assurance as Assurance],
        boot_state: o.boot, device_locked: o.locked, issued_at: issuedAt,
        chain_trusted: o.chainTrusted ?? true, keybox_revoked: o.kbRevoked ?? false,
        cross_level_reuse: o.xlReuse ?? false, strongbox_chain_missing: o.sbMissing ?? false,
        device_prop_mismatch: o.propMismatch ?? false, boot_state_spoofer: o.bootSpoofer ?? false,
        software_attested: o.swAttest ?? false,
      };
    } catch { return null; }
  }
  private _mac(data: Buffer): Buffer {
    return createHmac("sha256", this.key).update(data).digest();
  }
}
