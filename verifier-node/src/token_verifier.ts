// The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts.
import { verify as cryptoVerify, X509Certificate } from "node:crypto";
import { decryptHex } from "./keystream.js";
import { Policy, defaultPolicy } from "./policy.js";
import { SignalRegistry } from "./registry.js";
import { pinnedRootsDefault } from "./pinned_roots.js";
import { challenge as attChallenge, fields as attFields } from "./attestation.js";
import { parseChain, verifyToPinnedRoot } from "./chain_verifier.js";
import { resolve as resolveSignals, device as deviceOf } from "./signals.js";
import { Check, CheckKind, Decision, ResolvedSignal, VerificationResult } from "./models.js";

const BINDING_SEP = "\n--BINDING\n";
const FS = "\x1F";

export class TokenVerifier {
  private registry: SignalRegistry;
  private policy: Policy;
  private pinnedRoots: X509Certificate[];
  constructor(registry?: SignalRegistry, policy?: Policy, pinnedRoots?: X509Certificate[]) {
    this.registry = registry ?? SignalRegistry.bundled();
    this.policy = policy ?? defaultPolicy();
    this.pinnedRoots = pinnedRoots ?? pinnedRootsDefault();
  }

  verify(tokenHex: string, issuedNonce: string): VerificationResult {
    const checks: Check[] = [];
    const auth = (name: string, ok: boolean, detail = ""): boolean => {
      checks.push({ name, ok, detail, kind: CheckKind.AUTH }); return ok;
    };
    const integ = (name: string, ok: boolean, detail = ""): boolean => {
      checks.push({ name, ok, detail, kind: CheckKind.INTEGRITY }); return ok;
    };
    const run = <T>(fn: () => T): { ok: true; value: T } | { ok: false; error: string } => {
      try { return { ok: true, value: fn() }; }
      catch (e: any) { return { ok: false, error: e?.message ?? String(e) }; }
    };

    const text = decryptHex(tokenHex);
    const sep = text.indexOf(BINDING_SEP);
    const signed = sep >= 0 ? text.slice(0, sep) : text;
    const binding = sep >= 0 ? text.slice(sep + BINDING_SEP.length) : "";
    const parsed = run(() => JSON.parse(signed) as any);
    const doc: any = parsed.ok ? parsed.value : {};

    if (!auth("binding present", sep >= 0, sep >= 0 ? "" : "unbound/legacy token"))
      return this.result(checks, doc);
    if (!doc || typeof doc !== "object" || Object.keys(doc).length === 0) {
      auth("signed content is JSON", false, "unparseable signed_content");
      return this.result(checks, doc);
    }

    const tokenNonce = doc.nonce ?? "";
    auth("nonce matches issued", tokenNonce === issuedNonce);

    let sigHex = ""; const certsHex: string[] = [];
    for (const line of binding.split("\n")) {
      if (line.startsWith("SIG" + FS)) sigHex = line.slice(4);
      else if (line.startsWith("CERT" + FS)) certsHex.push(line.slice(5));
    }
    if (!auth("chain + signature present", sigHex.length > 0 && certsHex.length > 0))
      return this.result(checks, doc);

    const chain = run(() => parseChain(certsHex));
    if (!chain.ok || chain.value.length === 0) {
      auth("chain parses", false, "could not parse cert chain");
      return this.result(checks, doc);
    }
    const leaf = chain.value[0];

    const root = run(() => verifyToPinnedRoot(chain.value, this.pinnedRoots));
    auth("chain -> pinned Google root", root.ok,
         root.ok ? (root.value as X509Certificate).subject : root.error);

    const chal = run(() => attChallenge(leaf));
    auth("attestation challenge == nonce",
         chal.ok && chal.value.toString("hex") === issuedNonce.toLowerCase());

    const sigOk = run(() => cryptoVerify("sha256", Buffer.from(signed, "utf8"),
        leaf.publicKey, Buffer.from(sigHex, "hex"))).ok;
    auth("signature over verdict", sigOk, sigOk ? "" : "ECDSA verify failed");

    const f = run(() => attFields(leaf));
    const fields = f.ok ? f.value : null;
    integ("hardware security level >= TEE",
          fields !== null && (fields.securityLevel === 1 || fields.securityLevel === 2),
          fields ? String(fields.securityLevel) : "parse error");
    integ("verified boot state = Verified",
          fields !== null && fields.verifiedBootState === 0,
          fields ? String(fields.verifiedBootState) : "parse error");
    integ("device locked", fields !== null && fields.deviceLocked === true,
          fields ? String(fields.deviceLocked) : "parse error");

    return this.result(checks, doc);
  }

  private result(checks: Check[], doc: any): VerificationResult {
    const authentic = checks.filter(c => c.kind === CheckKind.AUTH).every(c => c.ok);
    const deviceOk = checks.filter(c => c.kind === CheckKind.INTEGRITY).every(c => c.ok);
    const signals: ResolvedSignal[] = resolveSignals(doc, this.registry, this.policy);
    const blocking = signals.some(s => s.blocking);
    const decision = !authentic ? Decision.REJECT :
      (!deviceOk || blocking) ? Decision.COMPROMISED : Decision.TRUSTWORTHY;
    return {
      decision, authentic, deviceIntegrityOk: deviceOk, checks: [...checks],
      schemaVersion: doc.schemaVersion ?? null, point: doc.point ?? null,
      ts: doc.ts ?? null, nonce: doc.nonce ?? null,
      device: deviceOf(doc), signals,
    };
  }
}
