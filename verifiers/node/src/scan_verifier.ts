import { createHash, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { X509Certificate } from "node:crypto";
import { AttestationCrl } from "./crl.js";
import { pinnedRootsDefault } from "./pinned_roots.js";
import { SignalRegistry } from "./registry.js";
import { defaultPolicy, Policy, isBlocking } from "./policy.js";
import { resolve as resolveSignals, parseAttrs, device as deviceOf } from "./signals.js";
import { Check, CheckKind, Decision, ResolvedSignal, ScanResult, ScanSession,
         Assurance, DeviceFingerprint, AttestationLevel } from "./models.js";

const FS = "\x1F";
const BINDING_SEP = "\n--BINDING\n";

export function bootStateSpoofer(reported: any, fields: any): boolean {
  const vbs = (reported?.vbs ?? "").toLowerCase();
  const flashLocked = reported?.blocked ?? "";
  const vbmeta = (reported?.vbmeta ?? "").toLowerCase();
  const selfClaimsClean = vbs === "green" || flash_locked === "1" || vbmeta === "locked";
  const attestClean = fields !== null && fields.verified_boot_state === 0 && fields.device_locked === true;
  return selfClaimsClean && !attestClean;
}

function hexOk(s: any): boolean {
  return typeof s === "string" && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

function fingerprintOf(doc: any): DeviceFingerprint | null {
  const fp = doc.fp;
  if (!fp) return null;
  const s = (k: string) => typeof fp[k] === "string" && fp[k] ? fp[k] : null;
  return { id: s("id"), aid: s("aid"), securityLevel: s("lvl"), build: s("build"),
           kernel: s("kernel"), patch: s("patch"), installer: s("installer") };
}

interface AttestationReport { level: AttestationLevel; signed: AttestationLevel;
  reason: string; detail: string | null; degraded: boolean; }

function attestationOf(doc: any): AttestationReport | null {
  const a = doc.attestation;
  if (!a) return null;
  const level = AttestationLevel.parse(a.level);
  const signed = AttestationLevel.parse(a.signed);
  return { level, signed, reason: a.reason || "UNKNOWN", detail: a.detail || null,
           degraded: signed !== AttestationLevel.ATTESTED };
}

export class ScanVerifier {
  private registry: SignalRegistry;
  private policy: Policy;
  private licenses: { isLicensed(pkg: string, signer: string): boolean };
  private crl: AttestationCrl;
  private pinnedRoots: X509Certificate[];
  private now: () => number;
  constructor(opts: { pinnedRoots?: X509Certificate[]; crl?: AttestationCrl;
      registry?: SignalRegistry; policy?: Policy;
      licenses?: { isLicensed(pkg: string, signer: string): boolean };
      now?: () => number } = {}) {
    this.pinnedRoots = opts.pinnedRoots ?? pinnedRootsDefault();
    this.crl = opts.crl ?? AttestationCrl.fromFile(
      new URL("../../fixtures/attestation-crl.txt", import.meta.url).pathname);
    this.registry = opts.registry ?? SignalRegistry.bundled();
    this.policy = opts.policy ?? defaultPolicy();
    this.licenses = opts.licenses ?? { isLicensed: () => true };
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }
  verifyScan(token: string, issuedSessionId: string, serverPriv: any,
             session: ScanSession | null = null): ScanResult {
    const checks: Check[] = [];
    const ck = (name: string, ok: boolean, detail = "") =>
      (checks.push({ name, ok, detail, kind: CheckKind.AUTH }), ok);
    const fail = (reason: string, signals: ResolvedSignal[] = []) =>
      ({ ok: false, bootstrap: false, deviceIntegrityOk: false, session: null,
         checks: [...checks], signals, reason, fingerprint: fingerprintOf(doc ?? {}) });

    let doc: any = {};
    if (!ck("v2 envelope", token.startsWith("2:"))) return fail("not a v2 token");
    let text: string;
    try {
      const p = Buffer.from(token.slice(2), "hex");
      const version = p[0], epoch = p[1];
      const ephPub = p.subarray(2, 34), nonce = p.subarray(34, 46);
      const ctAndTag = p.subarray(46);
      const eph = Buffer.from(ephPub); eph[31] &= 0x7f;
      const shared = diffieHellman(serverPriv, createPublicKey({
        key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), eph]),
        format: "der", type: "spki" }));
      const key = hkdfSync("sha256", shared, nonce,
        Buffer.concat([Buffer.from("intel-token-v2"), Buffer.of(epoch)]), 32);
      const d = createDecipheriv("aes-256-gcm", Buffer.from(key), nonce);
      d.setAAD(Buffer.concat([Buffer.of(version, epoch), ephPub]));
      d.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
      text = Buffer.concat([d.update(ctAndTag.subarray(0, ctAndTag.length - 16)),
                            d.final()]).toString("utf8");
    } catch { return fail("envelope did not open"); }
    void doc;
    if (!ck("envelope opens", true)) return fail("envelope did not open");
    const sep = text.indexOf(BINDING_SEP);
    if (!ck("binding present", sep >= 0)) return fail("unbound");
    const signed = text.slice(0, sep), binding = text.slice(sep + BINDING_SEP.length);
    try { doc = JSON.parse(signed); } catch { doc = {}; }
    if (!ck("signed content is JSON", Object.keys(doc).length > 0)) return fail("bad json");
    void ck; void fail; void doc;
    return this._continueScan(doc, binding, issuedSessionId, serverPriv, session, checks);
  }
  private _continueScan(doc: any, binding: string, issuedSessionId: string, serverPriv: any,
                        session: ScanSession | null, checks: Check[]): ScanResult {
    const bootstrap = doc.bootstrap === true;
    const att = attestationOf(doc);
    let signals: ResolvedSignal[] = resolveSignals(doc, this.registry, this.policy);
    const fail = (reason: string, s: ResolvedSignal[] = signals) => ({
      ok: false, bootstrap, deviceIntegrityOk: false, session: null, checks: [...checks],
      signals: s, reason, fingerprint: fingerprintOf(doc) });
    if (doc.sessionId !== issuedSessionId) {
      checks.push({ name: "session id matches issued", ok: false, detail: "", kind: CheckKind.AUTH });
      return fail("session id mismatch");
    }
    const sigHex = bindingSig(binding);
    const degraded = att !== null && (att.degraded || !sigHex);
    if (degraded) {
      checks.push({ name: "token carries a hardware-attested binding", ok: false,
        detail: `${att!.reason} (signed=${att!.signed})`, kind: CheckKind.AUTH });
      const extra = degradedSignals(att!, this.registry, this.policy)
        .filter(s => !signals.some(x => x.id === s.id));
      return fail("unattested: " + att!.reason, [...signals, ...extra]);
    }
    if (doc.sessionId !== issuedSessionId) return fail("session id mismatch");
    return bootstrap ? this._bootstrap(doc, binding, issuedSessionId, checks, signals)
                     : this._steadyState(doc, binding, signed, session, checks, signals);
  }
  private _bootstrap(doc: any, binding: string, issuedSessionId: string,
                     checks: Check[], signals: ResolvedSignal[]): ScanResult {
    const fail = (reason: string) => ({ ok: false, bootstrap: true, deviceIntegrityOk: false,
      session: null, checks: [...checks], signals, reason, fingerprint: fingerprintOf(doc) });
    const certs: string[] = [], sb: string[] = [], tee: string[] = [];
    for (const line of binding.split("\n")) {
      if (line.startsWith("CERT")) certs.push(line.slice(5));
      else if (line.startsWith("XLEVEL_SB")) sb.push(line.slice(10));
      else if (line.startsWith("XLEVEL_TEE")) tee.push(line.slice(11));
    }
    if (!certs.length) return fail("no chain");
    let chain: X509Certificate[];
    try { chain = parseChain(certs); } catch { return fail("chain parse"); }
    if (!chain.length) return fail("chain parse");
    const leaf = chain[0];
    let root: X509Certificate;
    try { root = verifyToPinnedRoot(chain, this.pinnedRoots); }
    catch (e: any) {
      checks.push({ name: "chain -> pinned Google root", ok: false, detail: e.message,
                    kind: CheckKind.AUTH });
      return fail("chain does not reach a pinned Google root");
    }
    checks.push({ name: "chain -> pinned Google root", ok: true,
                  detail: root.subjectX500Primitive?.toString?.() ?? "", kind: CheckKind.AUTH });
    let challenge: Buffer | null = null;
    try { challenge = attestationChallenge(leaf); } catch { /* absent */ }
    const chalOk = challenge !== null && challenge.equals(Buffer.from(issuedSessionId, "utf8"));
    checks.push({ name: "attestation challenge == session id", ok: chalOk, detail: "",
                  kind: CheckKind.AUTH });
    if (!chalOk) return fail("attestation not bound to this session");
    const spki = doc.attestedKey;
    if (!hexOk(spki)) return fail("attestedKey missing or not hex");
    let fields: any = null, platform: any = { osVersion: null, osPatchLevel: null,
      vendorPatchLevel: null, bootPatchLevel: null };
    try { fields = attestationFields(leaf); } catch { fields = null; }
    try { platform = attestedPlatform(leaf); } catch { platform = { osVersion: null,
      osPatchLevel: null, vendorPatchLevel: null, bootPatchLevel: null }; }
    const assurance = fields?.securityLevel === 2 ? Assurance.STRONGBOX :
                      fields?.securityLevel === 1 ? Assurance.TEE : Assurance.SOFTWARE;
    const softwareAttested = fields?.securityLevel === 0;
    let reuse = false, sbMissing = false;
    try {
      const x = crossLevelCheck(sb, tee, assurance, this.pinnedRoots);
      reuse = x.reuse; sbMissing = x.strongboxChainMissing;
    } catch { /* fail open */ }
    let revokedSerial: string | null = null;
    try {
      revokedSerial = this.crl.firstRevoked(chain,
        sb.length >= 2 ? parseChain(sb) : [], tee.length >= 2 ? parseChain(tee) : []);
    } catch { revokedSerial = null; }
    const reported = doc.device ?? {};
    let propMismatch: string | null = null;
    let attestedProps: Record<string, string> = {};
    try { attestedProps = deviceProperties(leaf); } catch { attestedProps = {}; }
    for (const [k, a] of Object.entries(attestedProps)) {
      const r = reported[k];
      if (typeof r === "string" && a && r && a.toLowerCase() !== r.toLowerCase())
        propMismatch = `attested ${k}='${a}' != reported '${r}'`;
    }
    const spoofer = bootStateSpoofer(reported, fields);
    const sbFeature = { "1": true, "0": false }[reported.sbFeature as string] ?? null;
    const strongboxTransient = assurance !== Assurance.STRONGBOX && sb.length < 2 && sbFeature === true;
    const session: ScanSession = {
      attestedKey: spki, attestedApp: attestedAppOf(leaf), assurance,
      bootState: fields?.bootStateName ?? "?", deviceLocked: fields?.deviceLocked === true,
      chainTrusted: true, keyboxRevoked: revokedSerial !== null, crossLevelReuse: reuse,
      devicePropMismatch: propMismatch !== null, bootStateSpoofer: spoofer,
      strongboxChainMissing: sbMissing || strongboxTransient,
      softwareAttested, osPatchLevel: platform.osPatchLevel,
      vendorPatchLevel: platform.vendorPatchLevel, bootPatchLevel: platform.bootPatchLevel,
      fingerprint: fingerprintOf(doc) };
    return adjudicate(doc, session, checks, signals, revokedSerial,
                      propMismatch, true, this.registry, this.policy, this.licenses);
  }
  private _steadyState(doc: any, binding: string, signed: string, session: ScanSession | null,
                       checks: Check[], signals: ResolvedSignal[]): ScanResult {
    const registry = this.registry, policy = this.policy;
    const all = [...signals,
      ...(session ? appSignals(doc, session.attestedApp, this.licenses, registry, policy) : []),
      ...(session ? carriedSignals(session, registry, policy) : [])];
    const fail = (reason: string) => ({ ok: false, bootstrap: false, deviceIntegrityOk: false,
      session: null, checks: [...checks], signals: all, reason, fingerprint: fingerprintOf(doc) });
    if (!session) {
      checks.push({ name: "session carried from bootstrap", ok: false, detail: "",
                    kind: CheckKind.AUTH });
      return fail("no bound key for session");
    }
    checks.push({ name: "session carried from bootstrap", ok: true, detail: "",
                  kind: CheckKind.AUTH });
    const sigHex = bindingSig(binding);
    if (!sigHex) {
      checks.push({ name: "signature present", ok: false, detail: "", kind: CheckKind.AUTH });
      return fail("no signature");
    }
    let verified = false;
    try {
      const pub = createPublicKey({ key: Buffer.from(session.attestedKey, "hex"),
                                    format: "der", type: "spki" });
      verified = cryptoVerify("sha256", Buffer.from(signed, "utf8"), pub, Buffer.from(sigHex, "hex"));
    } catch { verified = false; }
    checks.push({ name: "signature by the bound key", ok: verified, detail: "",
                  kind: CheckKind.AUTH });
    if (!verified) return fail("signature does not verify");
    return adjudicate(doc, session, checks, signals, null, null, false,
                      registry, policy, this.licenses);
  }
}
