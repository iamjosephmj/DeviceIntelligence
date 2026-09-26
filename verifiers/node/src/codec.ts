// JSON round-trip for ScanSession (ScanSessionCodec.kt port). Decode grades a
// truncated document DOWN to the suspicious value, never to the benign default.
import { ScanSession } from "./models.js";

const SUSPICIOUS = { chainTrusted: false, keyboxRevoked: true, crossLevelReuse: true,
  devicePropMismatch: true, bootStateSpoofer: true, strongboxChainMissing: true,
  softwareAttested: true };

export function decode(jsonText: string): ScanSession {
  const o = JSON.parse(jsonText);
  const key = o.attestedKey;
  if (typeof key !== "string") throw new Error("session has no attestedKey");
  const assurance = Assurance[o.assurance as keyof typeof Assurance] ?? Assurance.SOFTWARE;
  return {
    attestedKey: key,
    attestedApp: o.attestedApp ? {
      packageNames: o.attestedApp.packageNames ?? [],
      signatureDigests: o.attestedApp.signatureDigests ?? [] } : null,
    assurance,
    bootState: o.bootState ?? "?",
    deviceLocked: o.deviceLocked === true,
    chainTrusted: o.chainTrusted === true,
    keyboxRevoked: o.keyboxRevoked !== false,
    crossLevelReuse: o.crossLevelReuse !== false,
    devicePropMismatch: o.devicePropMismatch !== false,
    bootStateSpoofer: o.bootStateSpoofer !== false,
    strongboxChainMissing: o.strongboxChainMissing !== false,
    softwareAttested: o.softwareAttested !== false,
    osPatchLevel: o.osPatchLevel ?? null,
    vendorPatchLevel: o.vendorPatchLevel ?? null,
    bootPatchLevel: o.bootPatchLevel ?? null,
    fingerprint: o.fingerprint ? {
      id: o.fingerprint.id ?? null, aid: o.fingerprint.aid ?? null,
      securityLevel: o.fingerprint.securityLevel ?? null, build: o.fingerprint.build ?? null,
      kernel: o.fingerprint.kernel ?? null, patch: o.fingerprint.patch ?? null,
      installer: o.fingerprint.installer ?? null } : null,
  };
}

export function encode(s: ScanSession): string {
  const f: string[] = [`"attestedKey":${JSON.stringify(s.attestedKey)}`];
  if (s.attestedApp === null) f.push('"attestedApp":null');
  else f.push(`"attestedApp":{"packageNames":${JSON.stringify(s.attestedApp.packageNames)},` +
      `"signatureDigests":${JSON.stringify(s.attestedApp.signatureDigests)}}`);
  f.push(`"assurance":"${s.assurance}"`, `"bootState":${JSON.stringify(s.bootState)}`,
      `"deviceLocked":${s.deviceLocked}`, `"chainTrusted":${s.chainTrusted}`,
      `"keyboxRevoked":${s.keyboxRevoked}`, `"crossLevelReuse":${s.crossLevelReuse}`,
      `"devicePropMismatch":${s.devicePropMismatch}`, `"bootStateSpoofer":${s.bootStateSpoofer}`,
      `"strongboxChainMissing":${s.strongboxChainMissing}`,
      `"softwareAttested":${s.softwareAttested}`,
      `"osPatchLevel":${s.osPatchLevel ?? "null"}`,
      `"vendorPatchLevel":${s.vendorPatchLevel ?? "null"}`,
      `"bootPatchLevel":${s.bootPatchLevel ?? "null"}`);
  if (s.fingerprint === null) f.push('"fingerprint":null');
  else {
    const fp = s.fingerprint;
    const pairs = (["id","aid","securityLevel","build","kernel","patch","installer"] as const)
      .map(k => `${JSON.stringify(k)}:${fp[k] === null ? "null" : JSON.stringify(fp[k])}`)
      .join(",");
    f.push(`"fingerprint":{${pairs}}`);
  }
  return "{" + f.join(",") + "}";
}
