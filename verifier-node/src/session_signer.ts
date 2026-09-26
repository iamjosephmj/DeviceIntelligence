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
      pinnedKey: s.pinnedKeySpkiHex, assurance: s.assurance, boot: s.bootState,
      locked: s.deviceLocked, issuedAt: s.issuedAt, chainTrusted: s.chainTrusted,
      kbRevoked: s.keyboxRevoked, xlReuse: s.crossLevelReuse,
      sbMissing: s.strongboxChainMissing, propMismatch: s.devicePropMismatch,
      bootSpoofer: s.bootStateSpoofer, swAttest: s.softwareAttested,
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
        bootState: o.boot, deviceLocked: o.locked, issuedAt: issuedAt,
        chainTrusted: o.chainTrusted ?? true, keyboxRevoked: o.kbRevoked ?? false,
        crossLevelReuse: o.xlReuse ?? false, strongboxChainMissing: o.sbMissing ?? false,
        devicePropMismatch: o.propMismatch ?? false, bootStateSpoofer: o.bootSpoofer ?? false,
        softwareAttested: o.swAttest ?? false,
      };
    } catch { return null; }
  }
  private _mac(data: Buffer): Buffer {
    return createHmac("sha256", this.key).update(data).digest();
  }
}
