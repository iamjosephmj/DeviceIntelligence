import { decryptHex } from "./keystream.js";
import { resolve as resolveSignals, device } from "./signals.js";
import { DecodedToken } from "./models.js";

export const BINDING_SEP = "\n--BINDING\n";

export class TokenDecoder {
  decode(tokenHex: string, registry: any, policy: any): DecodedToken {
    const text = decryptHex(tokenHex);
    const idx = text.indexOf(BINDING_SEP);
    const signed = idx >= 0 ? text.slice(0, idx) : text;
    const doc = JSON.parse(signed);
    return {
      schemaVersion: doc.schemaVersion ?? null, point: doc.point ?? null,
      ts: doc.ts ?? null, nonce: doc.nonce ?? null,
      device: device(doc), signals: resolveSignals(doc, registry, policy),
      hasBinding: idx >= 0,
    };
  }
}
