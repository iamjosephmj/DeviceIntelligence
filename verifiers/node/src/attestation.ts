import { readTlv, tlvList, sequenceElements, Tlv } from "./der.js";
import { AttestationFields, AttestedApp, AttestedPlatform } from "./models.js";

export const OID = "1.3.6.1.4.1.11129.2.1.17";
const ROOT_OF_TRUST_TAG = Buffer.from([0xbf, 0x85, 0x40]);
const ATTEST_APP_ID_TAG = Buffer.from([0xbf, 0x85, 0x45]);
const OS_VERSION_TAG = Buffer.from([0xbf, 0x85, 0x41]);
const OS_PATCH_LEVEL_TAG = Buffer.from([0xbf, 0x85, 0x42]);
const VENDOR_PATCH_TAG = Buffer.from([0xbf, 0x85, 0x4e]);
const BOOT_PATCH_TAG = Buffer.from([0xbf, 0x85, 0x4f]);
const ATTEST_ID: Array<[string, Buffer]> = [
  ["brand", Buffer.from([0xbf, 0x85, 0x46])], ["device", Buffer.from([0xbf, 0x85, 0x47])],
  ["product", Buffer.from([0xbf, 0x85, 0x48])], ["manufacturer", Buffer.from([0xbf, 0x85, 0x4c])],
  ["model", Buffer.from([0xbf, 0x85, 0x4d])],
];

function keyDescriptionDer(cert: { getExtensionValueRaw(oid: string): Buffer | null }): Buffer {
  const raw = cert.getExtensionValueRaw(OID);
  if (raw === null) throw new Error("no Android attestation extension on leaf");
  const [octet] = readTlv(raw, 0);
  return Buffer.from(octet.value);
}

export function challenge(cert: any): Buffer {
  const elems = sequenceElements(keyDescriptionDer(cert));
  return Buffer.from(elems[4].value);
}

export function fields(cert: any): AttestationFields {
  const elems = sequenceElements(keyDescriptionDer(cert));
  const securityLevel = elems.length > 1 && elems[1].value.length
    ? elems[1].value[0] & 0xff : null;
  let bootState: number | null = null, locked: boolean | null = null;
  for (const authIdx of [7, 6]) {
    if (elems.length <= authIdx) continue;
    for (const tlv of tlvList(elems[authIdx].value)) {
      if (tlv.tag.equals(ROOT_OF_TRUST_TAG)) {
        const [inner] = readTlv(tlv.value, 0);
        const rot = tlvList(inner.value);
        if (rot.length > 1 && rot[1].value.length) locked = rot[1].value[0] !== 0;
        if (rot.length > 2 && rot[2].value.length) bootState = rot[2].value[0] & 0xff;
        break;
      }
    }
    if (bootState !== null) break;
  }
  return { securityLevel, verifiedBootState: bootState, deviceLocked: locked };
}

export function deviceProperties(cert: any): Record<string, string> {
  const elems = sequenceElements(keyDescriptionDer(cert));
  const out: Record<string, string> = {};
  for (const authIdx of [7, 6]) {
    if (elems.length <= authIdx) continue;
    for (const tlv of tlvList(elems[authIdx].value)) {
      for (const [name, tag] of ATTEST_ID) {
        if (tlv.tag.equals(tag) && !(name in out)) {
          const [octet] = readTlv(tlv.value, 0);
          out[name] = octet.value.toString("ascii");
        }
      }
    }
  }
  return out;
}

export function attestedApp(cert: any): AttestedApp | null {
  const elems = sequenceElements(keyDescriptionDer(cert));
  for (const authIdx of [6, 7]) {
    if (elems.length <= authIdx) continue;
    for (const tlv of tlvList(elems[authIdx].value)) {
      if (!tlv.tag.equals(ATTEST_APP_ID_TAG)) continue;
      const [octet] = readTlv(tlv.value, 0);
      const inner = sequenceElements(octet.value);
      const pkgs = tlvList(inner[0].value).map(info => tlvList(info.value)[0].value.toString("utf8"));
      const digests = tlvList(inner[1].value).map(t => t.value.toString("hex"));
      if (!pkgs.length && !digests.length) return null;
      return { packageNames: pkgs, signatureDigests: digests };
    }
  }
  return null;
}

export function attestedPlatform(cert: any): AttestedPlatform {
  let os: number | null = null, osP: number | null = null, vP: number | null = null, bP: number | null = null;
  try {
    const elems = sequenceElements(keyDescriptionDer(cert));
    for (const authIdx of [7, 6]) {
      if (elems.length <= authIdx) continue;
      for (const tlv of tlvList(elems[authIdx].value)) {
        try {
          const [inner] = readTlv(tlv.value, 0);
          let acc = 0;
          for (const b of inner.value) acc = (acc << 8) | (b & 0xff);
          if (tlv.tag.equals(OS_VERSION_TAG) && os === null) os = acc;
          else if (tlv.tag.equals(OS_PATCH_LEVEL_TAG) && osP === null) osP = acc;
          else if (tlv.tag.equals(VENDOR_PATCH_TAG) && vP === null) vP = acc;
          else if (tlv.tag.equals(BOOT_PATCH_TAG) && bP === null) bP = acc;
        } catch { /* skip */ }
      }
    }
  } catch { /* fail open */ }
  return { osVersion: os, osPatchLevel: osP, vendorPatchLevel: vP, bootPatchLevel: bP };
}
