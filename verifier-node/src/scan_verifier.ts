// The scan verification flow (ScanVerifier.kt port): bootstrap, steady-state,
// adjudication, and the boot-state spoofer truth table.
import { createDecipheriv, createPublicKey, createHash, diffieHellman, hkdfSync,
         verify as cryptoVerify, X509Certificate } from "node:crypto";
import { AttestationCrl } from "./crl.js";
import { pinnedRootsDefault } from "./pinned_roots.js";
import { SignalRegistry } from "./registry.js";
import { Policy, defaultPolicy, isBlocking } from "./policy.js";
import { resolve as resolveSignals } from "./signals.js";
import { attestationLevelParse, AttestationLevel, Check, CheckKind, ResolvedSignal,
         ScanResult, ScanSession, Assurance, DeviceFingerprint, AttestedApp,
         AttestationFields, AttestedPlatform, bootStateName } from "./models.js";
import { challenge as attChallenge, fields as attFields,
         attestedApp as attApp, attestedPlatform as attPlatform,
         deviceProperties as attProps } from "./attestation.js";
import { parseChain, verifyToPinnedRoot } from "./chain_verifier.js";

const FS = "\x1F";
const BINDING_SEP = "\n--BINDING\n";

export function bootStateSpoofer(reported: any, fields: AttestationFields | null): boolean {
  const vbs = (reported?.vbs ?? "").toLowerCase();
  const flashLocked = reported?.blocked ?? "";
  const vbmeta = (reported?.vbmeta ?? "").toLowerCase();
  const selfClaimsClean = vbs === "green" || flashLocked === "1" || vbmeta === "locked";
  const attestClean = fields !== null && fields.verifiedBootState === 0 &&
      fields.deviceLocked === true;
  return selfClaimsClean && !attestClean;
}

function hexOk(s: any): boolean {
  return typeof s === "string" && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

function fingerprintOf(doc: any): DeviceFingerprint | null {
  const fp = doc.fp;
  if (!fp) return null;
  const s = (k: string) => (typeof fp[k] === "string" && fp[k]) ? fp[k] : null;
  return { id: s("id"), aid: s("aid"), securityLevel: s("lvl"), build: s("build"),
           kernel: s("kernel"), patch: s("patch"), installer: s("installer") };
}

interface AttestationReport {
  level: AttestationLevel; signed: AttestationLevel;
  reason: string; detail: string | null; degraded: boolean;
}

function attestationOf(doc: any): AttestationReport | null {
  const a = doc.attestation;
  if (!a) return null;
  const level = attestationLevelParse(a.level);
  const signed = attestationLevelParse(a.signed);
  return { level, signed, reason: a.reason || "UNKNOWN", detail: a.detail || null,
           degraded: signed !== AttestationLevel.ATTESTED };
}

function bindingSig(binding: string): string {
  for (const line of binding.split("\n"))
    if (line.startsWith("SIG" + FS)) return line.slice(4);
  return "";
}

function carriedSignals(session: ScanSession, registry: SignalRegistry,
                        policy: Policy): ResolvedSignal[] {
  const out: ResolvedSignal[] = [];
  const add = (id: string, detail: string) => {
    const m = registry.get(id);
    if (m) out.push({ id: m.id, detector: m.detector, kind: m.kind, title: m.title,
      severity: m.severity, detail, blocking: isBlocking(policy, m.id, m.severity),
      attributes: {} });
  };
  if (session.bootStateSpoofer)
    add("INTEL_0055", "self-report=green/locked but hardware attestation disagrees");
  if (session.crossLevelReuse)
    add("INTEL_0016", "same attestation batch key across StrongBox and TEE — leaked keybox");
  if (session.strongboxChainMissing)
    add("INTEL_0045", "StrongBox hardware indicated but no StrongBox attestation chain produced");
  if (session.softwareAttested)
    add("INTEL_0056", "attestation reports securityLevel=Software — no hardware root of trust");
  return out;
}

function degradedSignals(att: AttestationReport, registry: SignalRegistry,
                         policy: Policy): ResolvedSignal[] {
  const out: ResolvedSignal[] = [];
  const add = (id: string, text: string) => {
    const m = registry.get(id);
    if (m) out.push({ id: m.id, detector: m.detector, kind: m.kind, title: m.title,
      severity: m.severity, detail: text, blocking: isBlocking(policy, m.id, m.severity),
      attributes: {} });
  };
  const detail = att.detail ? ` (${att.detail})` : "";
  if (att.reason === "NO_SESSION")
    add("INTEL_0023", `scan issued with no prepared session${detail}`);
  else if (["LICENCE_EXPIRED", "LICENCE_PKG_MISMATCH", "LICENCE_UNPARSEABLE"].includes(att.reason))
    add("INTEL_0038", `licence rejected at scan time: ${att.reason}${detail}`);
  else
    add("INTEL_0030", `attestation unavailable: ${att.reason}${detail}`);
  if (att.signed === AttestationLevel.NONE)
    add("INTEL_0015", "token carries no signature");
  return out;
}

function appSignals(doc: any, attested: AttestedApp | null,
                    licenses: { isLicensed(pkg: string, signer: string): boolean },
                    registry: SignalRegistry, policy: Policy): ResolvedSignal[] {
  if (attested === null) return [];
  const app = doc.app;
  if (!app) return [];
  const pkg = app.package || "";
  const signer = app.signer || "";
  if (!pkg || !signer) return [];
  const mk = (id: string, detail: string): ResolvedSignal[] => {
    const m = registry.get(id);
    return m ? [{ id: m.id, detector: m.detector, kind: m.kind, title: m.title,
      severity: m.severity, detail, blocking: isBlocking(policy, m.id, m.severity),
      attributes: {} }] : [];
  };
  const agrees = attested.packageNames.includes(pkg) &&
    attested.signatureDigests.some(d => d.toLowerCase() === signer.toLowerCase());
  if (!agrees)
    return mk("INTEL_0046", `reported=${pkg}/${signer.slice(0, 16)}… ` +
      `attested=${attested.packageNames[0] ?? "?"}`);
  if (!licenses.isLicensed(pkg, signer)) return mk("INTEL_0037", `package=${pkg}`);
  return [];
}

function patchSignals(doc: any, session: ScanSession, policy: Policy, now: number,
                      registry: SignalRegistry): ResolvedSignal[] {
  const out: ResolvedSignal[] = [];
  const add = (id: string, detail: string) => {
    const m = registry.get(id);
    if (m) out.push({ id: m.id, detector: m.detector, kind: m.kind, title: m.title,
      severity: m.severity, detail, blocking: isBlocking(policy, m.id, m.severity),
      attributes: {} });
  };
  const toEpoch = (v: number): number | null => {
    try {
      const [y, m, d] = v > 999999 ? [Math.trunc(v / 10000), Math.trunc(v / 100) % 100, v % 100]
                                   : [Math.trunc(v / 100), v % 100, 1];
      if (m < 1 || m > 12 || d < 1 || d > 31) return null;
      return Date.UTC(y, m - 1, d) / 1000;
    } catch { return null; }
  };
  const epochs = [session.osPatchLevel, session.vendorPatchLevel, session.bootPatchLevel]
    .filter((x): x is number => x !== null).map(toEpoch).filter((x): x is number => x !== null);
  if (epochs.length) {
    const ageDays = Math.floor((now - Math.min(...epochs)) / 86_400);
    if (ageDays > policy.maxPatchAgeDays)
      add("INTEL_0050", `oldest attested patch is ${ageDays} days old ` +
        `(policy window ${policy.maxPatchAgeDays})`);
  }
  const reported = session.fingerprint?.patch ?? fingerprintOf(doc)?.patch ?? null;
  if (session.osPatchLevel !== null && reported) {
    let reportedMonth: number | null = null;
    try { reportedMonth = parseInt(reported.slice(0, 4)) * 100 + parseInt(reported.slice(5, 7)); }
    catch { reportedMonth = null; }
    if (reportedMonth !== null && reportedMonth !== session.osPatchLevel)
      add("INTEL_0019", `self-report ${reported} vs attested ${session.osPatchLevel}`);
  }
  return out;
}

function crossLevelCheck(sbHex: string[], teeHex: string[], assurance: Assurance,
                         pinnedRoots: X509Certificate[]): { reuse: boolean;
                                                            strongboxChainMissing: boolean } {
  if (assurance === Assurance.STRONGBOX && sbHex.length < 2)
    return { reuse: false, strongboxChainMissing: true };
  if (sbHex.length < 2 || teeHex.length < 2)
    return { reuse: false, strongboxChainMissing: false };
  const sbBatch = parseChain(sbHex)[1].publicKey;
  const teeBatch = parseChain(teeHex)[1].publicKey;
  return { reuse: sbBatch.equals(teeBatch), strongboxChainMissing: false };
}

function propMismatchFn(attested: Record<string, string>, reported: any): string | null {
  for (const [k, a] of Object.entries(attested)) {
    const r = reported[k];
    if (typeof r === "string" && a && r && a.toLowerCase() !== r.toLowerCase())
      return `attested ${k}='${a}' != reported '${r}'`;
  }
  return null;
}

function subjectOf(cert: X509Certificate): string {
  return cert.subject ?? cert.subject;
}

interface ScanOutcome {
  session?: ScanSession;
  fail?: ScanResult;
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
    this.crl = opts.crl ?? AttestationCrl.fromFile(new URL(
      "../resources/attestation-crl.txt", import.meta.url).pathname);
    this.registry = opts.registry ?? SignalRegistry.bundled();
    this.policy = opts.policy ?? defaultPolicy();
    this.licenses = opts.licenses ?? { isLicensed: () => true };
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  verifyScan(token: string, issuedSessionId: string, serverPriv: any,
             session: ScanSession | null = null): ScanResult {
    const checks: Check[] = [];
    let signals: ResolvedSignal[] = [];
    let doc: any = {};
    const ck = (name: string, ok: boolean, detail = "") => {
      checks.push({ name, ok, detail, kind: CheckKind.AUTH });
      return ok;
    };
    const fail = (reason: string, bootstrap = false,
                  extra: ResolvedSignal[] = []): ScanResult =>
      ({ ok: false, bootstrap, deviceIntegrityOk: false, session: null,
         checks: [...checks], signals: [...signals, ...extra], reason,
         fingerprint: fingerprintOf(doc ?? {}) });

    if (!ck("v2 envelope", token.startsWith("2:"))) return fail("not a v2 token");
    let text = "";
    try {
      const p = Buffer.from(token.slice(2), "hex");
      const version = p[0], epoch = p[1];
      const ephPub = p.subarray(2, 34), nonce = p.subarray(34, 46);
      const ctAndTag = p.subarray(46);
      const eph = Buffer.from(ephPub); eph[31] &= 0x7f;
      const shared = diffieHellman({
        privateKey: serverPriv,
        publicKey: createPublicKey({ key: Buffer.concat([
          Buffer.from("302a300506032b656e032100", "hex"), eph]),
          format: "der", type: "spki" }) });
      const key = Buffer.from(hkdfSync("sha256", shared, nonce,
        Buffer.concat([Buffer.from("intel-token-v2"), Buffer.of(epoch)]), 32));
      const d = createDecipheriv("aes-256-gcm", key, nonce);
      d.setAAD(Buffer.concat([Buffer.of(version, epoch), ephPub]));
      d.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
      text = Buffer.concat([d.update(ctAndTag.subarray(0, ctAndTag.length - 16)),
        d.final()]).toString("utf8");
      ck("envelope opens", true);
    } catch (e: any) {
      ck("envelope opens", false, e?.message ?? "");
      return fail("envelope did not open");
    }
    const sep = text.indexOf(BINDING_SEP);
    if (!ck("binding present", sep >= 0)) return fail("unbound");
    const signed = text.slice(0, sep), binding = text.slice(sep + BINDING_SEP.length);
    let parsed: any = {};
    let parsedOk = true;
    try { parsed = JSON.parse(signed); } catch { parsedOk = false; }
    doc = parsed;
    if (!ck("signed content is JSON", parsedOk && Object.keys(doc).length > 0))
      return fail("bad json");
    const bootstrap = doc.bootstrap === true;
    signals = resolveSignals(doc, this.registry, this.policy);
    const att = attestationOf(doc);
    const sigHex = bindingSig(binding);
    const degraded = att !== null && (att.degraded || !sigHex);
    if (degraded) {
      checks.push({ name: "token carries a hardware-attested binding", ok: false,
        detail: `${att!.reason} (signed=${att!.signed})`, kind: CheckKind.AUTH });
      const already = new Set(signals.map(s => s.id));
      const extra = degradedSignals(att!, this.registry, this.policy)
        .filter(s => !already.has(s.id));
      return fail(`unattested: ${att!.reason}`, bootstrap, extra);
    }
    if (doc.sessionId !== issuedSessionId) {
      checks.push({ name: "session id matches issued", ok: false, detail: "",
                    kind: CheckKind.AUTH });
      return fail("session id mismatch");
    }
    const outcome = bootstrap
      ? this._bootstrapFacts(doc, binding, issuedSessionId, checks)
      : this._steadyStateFacts(doc, binding, signed, session, checks, signals);
    if (outcome.fail) return outcome.fail;
    const sessionFacts = outcome.session!;
    const allSignals = [...signals,
      ...appSignals(doc, sessionFacts.attestedApp, this.licenses, this.registry, this.policy),
      ...carriedSignals(sessionFacts, this.registry, this.policy),
      ...patchSignals(doc, sessionFacts, this.policy, this.now(), this.registry)];
    const ok = checks.filter(c => c.kind === CheckKind.AUTH).every(c => c.ok);
    const integrityOk = checks.filter(c => c.kind === CheckKind.INTEGRITY).every(c => c.ok);
    const authFail = checks.find(c => c.kind === CheckKind.AUTH && !c.ok);
    return { ok, bootstrap, deviceIntegrityOk: integrityOk,
      session: bootstrap ? sessionFacts : null, checks: [...checks], signals: allSignals,
      reason: authFail?.name ?? null,
      fingerprint: sessionFacts.fingerprint ?? fingerprintOf(doc),
      attestation: this._attestationReport };
  }
  private _attestationReport: any = null;
  private _pendingExtra: ResolvedSignal[] = [];

  // ---- bootstrap facts: every hard gate, then the carried facts -------------
  private _bootstrapFacts(doc: any, binding: string, issuedSessionId: string,
                          checks: Check[]): ScanOutcome {
    const ck = (name: string, ok: boolean, detail = "") =>
      (checks.push({ name, ok, detail, kind: CheckKind.AUTH }), ok);
    const mkFail = (reason: string): ScanResult =>
      ({ ok: false, bootstrap: true, deviceIntegrityOk: false, session: null,
         checks: [...checks], signals: [], reason, fingerprint: fingerprintOf(doc) });
    const fail = (reason: string) => ({ fail: mkFail(reason) });

    const certs: string[] = [], sb: string[] = [], tee: string[] = [];
    for (const line of binding.split("\n")) {
      if (line.startsWith("CERT")) certs.push(line.slice(5));
      else if (line.startsWith("XLEVEL_SB")) sb.push(line.slice(10));
      else if (line.startsWith("XLEVEL_TEE")) tee.push(line.slice(11));
    }
    if (!ck("chain present", certs.length > 0)) return fail("no chain");
    let chain: X509Certificate[];
    try { chain = parseChain(certs); } catch { return fail("chain parse"); }
    if (!chain.length) return fail("chain parse");
    const leaf = chain[0];
    let root: X509Certificate;
    try { root = verifyToPinnedRoot(chain, this.pinnedRoots); }
    catch (e: any) {
      ck("chain -> pinned Google root", false, e.message);
      return fail("chain does not reach a pinned Google root");
    }
    ck("chain -> pinned Google root", true, root.subject ?? "");
    let challenge: Buffer | null = null;
    try { challenge = attChallenge(leaf); } catch { challenge = null; }
    const chalOk = challenge !== null && challenge.equals(Buffer.from(issuedSessionId, "utf8"));
    if (!ck("attestation challenge == session id", chalOk))
      return fail("attestation not bound to this session");
    const spki = doc.attestedKey;
    if (!ck("attested key present and hex", typeof spki === "string" && hexOk(spki)))
      return fail("attestedKey missing or not hex");
    let fields: any = null;
    try { fields = attFields(leaf); } catch { fields = null; }
    let platform: any = { osVersion: null, osPatchLevel: null, vendorPatchLevel: null,
      bootPatchLevel: null };
    try { platform = attPlatform(leaf); } catch { platform = platform; }
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
    try { attestedProps = attProps(leaf); } catch { attestedProps = {}; }
    for (const [k, a] of Object.entries(attestedProps)) {
      const r = reported[k];
      if (typeof r === "string" && a && r && a.toLowerCase() !== r.toLowerCase())
        propMismatch = `attested ${k}='${a}' != reported '${r}'`;
    }
    const spoofer = bootStateSpoofer(reported, fields);
    const sbFeature = { "1": true, "0": false }[reported.sbFeature as string] ?? null;
    const strongboxTransient = assurance !== Assurance.STRONGBOX && sb.length < 2 &&
      sbFeature === true;

    ck("attestation chain trusted", true);
    ck("no revoked keybox", revokedSerial === null,
       revokedSerial ? `revoked serial ${revokedSerial}` : "");
    ck("no cross-level keybox reuse", !reuse,
       reuse ? "same batch key across StrongBox and TEE — leaked keybox" : "");
    ck("device-property attestation matches self-report", propMismatch === null,
       propMismatch ?? "");
    ck("boot-state self-report matches hardware attestation", !spoofer,
       spoofer ? "self-report claims clean/locked boot but attestation says otherwise — prop spoofer"
               : "");
    const ik = (name: string, ok: boolean, detail = "") =>
      checks.push({ name, ok, detail, kind: CheckKind.INTEGRITY });
    ik("hardware security level >= TEE", assurance !== Assurance.SOFTWARE, assurance);
    ik("verified boot state = Verified",
        fields !== null && fields.verifiedBootState === 0 && fields.deviceLocked === true,
        fields ? bootStateName(fields) : "?");
    ik("device locked", fields?.deviceLocked === true, String(fields?.deviceLocked));

    return { session: {
      attestedKey: spki, attestedApp: attApp(leaf), assurance,
      bootState: fields ? bootStateName(fields) : "?", deviceLocked: fields?.deviceLocked === true,
      chainTrusted: true, keyboxRevoked: revokedSerial !== null, crossLevelReuse: reuse,
      devicePropMismatch: propMismatch !== null, bootStateSpoofer: spoofer,
      strongboxChainMissing: sbMissing || strongboxTransient,
      softwareAttested, osPatchLevel: platform.osPatchLevel,
      vendorPatchLevel: platform.vendorPatchLevel, bootPatchLevel: platform.bootPatchLevel,
      fingerprint: fingerprintOf(doc) } };
  }

  // ---- steady-state facts ---------------------------------------------------
  private _steadyStateFacts(doc: any, binding: string, signed: string,
                            session: ScanSession | null, checks: Check[],
                            signals: ResolvedSignal[]): ScanOutcome {
    const ck = (name: string, ok: boolean, detail = "") =>
      (checks.push({ name, ok, detail, kind: CheckKind.AUTH }), ok);
    const fail = (reason: string): ScanOutcome => ({
      fail: { ok: false, bootstrap: false, deviceIntegrityOk: false, session: null,
              checks: [...checks], signals: [...signals, ...this._pendingExtra], reason,
              fingerprint: fingerprintOf(doc) } });
    if (!session) {
      ck("session carried from bootstrap", false);
      return fail("no bound key for session");
    }
    ck("session carried from bootstrap", true);
    const sigHex = bindingSig(binding);
    if (!ck("signature present", Boolean(sigHex))) return fail("no signature");
    let verified = false;
    try {
      const pub = createPublicKey({ key: Buffer.from(session.attestedKey, "hex"),
                                    format: "der", type: "spki" });
      verified = cryptoVerify("sha256", Buffer.from(signed, "utf8"), pub,
                              Buffer.from(sigHex, "hex"));
    } catch { verified = false; }
    if (!ck("signature by the bound key", verified, "ECDSA verify failed"))
      return fail("signature does not verify");
    return { session };
  }
}
