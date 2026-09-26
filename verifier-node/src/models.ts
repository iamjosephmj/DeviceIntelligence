export enum Decision { TRUSTWORTHY = "TRUSTWORTHY", COMPROMISED = "COMPROMISED", REJECT = "REJECT" }
export enum CheckKind { AUTH = "AUTH", INTEGRITY = "INTEGRITY" }
export enum Assurance { SOFTWARE = "SOFTWARE", TEE = "TEE", STRONGBOX = "STRONGBOX" }
export enum AttestationLevel { ATTESTED = "ATTESTED", SOFTWARE = "SOFTWARE", NONE = "NONE" }

export function attestationLevelParse(s: string | null | undefined): AttestationLevel {
  for (const l of Object.values(AttestationLevel))
    if (l.toLowerCase() === (s ?? "").toLowerCase()) return l;
  return AttestationLevel.NONE;
}

export interface Check { name: string; ok: boolean; detail: string; kind: CheckKind; }

/** The licence question the verifier asks per (package, signer) pair. The
 *  default answers true for everything — inject a real entitlement store via
 *  ScanVerifier's opts.licenses (the Kotlin port's LicenseRegistry). */
export interface LicenseChecker {
  isLicensed(pkg: string, signer: string): boolean;
}
export interface DeviceInfo { api: number | null; abi: string | null; model: string | null; }

export interface ResolvedSignal {
  id: string; detector: string; kind: string; title: string;
  severity: string; detail: string; blocking: boolean;
  attributes: Record<string, string>;
  moduleId?: string; path?: string; linkedLibraries?: string[];
  linksHookLib?: string; hookedSymbol?: string; hookedBy?: string;
  hookStubRegions?: number;
}

export function isConfirmedHookPool(s: ResolvedSignal): boolean {
  return s.kind === "rwx_memory_mapping" && (s.hookStubRegions ?? 0) > 0;
}

export function definitiveHooks(signals: ResolvedSignal[]): string[] {
  const structural = new Set(signals
    .filter(s => s.kind === "libc_inline_hook" || s.kind === "libc_inline_stub")
    .map(s => s.hookedSymbol).filter(Boolean) as string[]);
  const behavioral = new Set(signals
    .filter(s => s.kind === "syscall_divergence")
    .map(s => s.hookedSymbol).filter(Boolean) as string[]);
  return [...structural].filter(x => behavioral.has(x)).sort();
}

export interface DecodedToken {
  schemaVersion: number | null; point: string | null; ts: number | null;
  nonce: string | null; device: DeviceInfo | null; signals: ResolvedSignal[];
  hasBinding: boolean;
}

export interface TokenAttestation {
  level: AttestationLevel; signed: AttestationLevel;
  reason: string; detail?: string;
  degraded: boolean;
}

export interface AttestedApp { packageNames: string[]; signatureDigests: string[]; }

export interface DeviceFingerprint {
  id: string | null; aid: string | null; securityLevel: string | null;
  build: string | null; kernel: string | null; patch: string | null;
  installer: string | null;
}

export interface AttestationFields {
  securityLevel: number | null; verifiedBootState: number | null;
  deviceLocked: boolean | null;
}

const BOOT_STATE_NAMES: Record<number, string> = {
  0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed" };

export function bootStateName(f: AttestationFields): string {
  if (f.verifiedBootState === null) return "?";
  return BOOT_STATE_NAMES[f.verifiedBootState] ?? String(f.verifiedBootState);
}

export interface AttestedPlatform {
  osVersion: number | null; osPatchLevel: number | null;
  vendorPatchLevel: number | null; bootPatchLevel: number | null;
}

export interface ScanSession {
  attestedKey: string; attestedApp: AttestedApp | null; assurance: Assurance;
  bootState: string; deviceLocked: boolean;
  chainTrusted: boolean; keyboxRevoked: boolean; crossLevelReuse: boolean;
  devicePropMismatch: boolean; bootStateSpoofer: boolean;
  strongboxChainMissing: boolean; softwareAttested: boolean;
  osPatchLevel: number | null; vendorPatchLevel: number | null;
  bootPatchLevel: number | null; fingerprint: DeviceFingerprint | null;
}

export interface ScanResult {
  ok: boolean; bootstrap: boolean; deviceIntegrityOk: boolean;
  session: ScanSession | null; checks: Check[]; signals: ResolvedSignal[];
  reason: string | null; fingerprint: DeviceFingerprint | null;
  attestation?: TokenAttestation;
}

export function blockingSignals(r: ScanResult): ResolvedSignal[] {
  return r.signals.filter(s => s.blocking);
}

export function scanDecision(r: ScanResult): Decision {
  if (!r.ok) return Decision.REJECT;
  if (!r.deviceIntegrityOk || blockingSignals(r).length > 0) return Decision.COMPROMISED;
  return Decision.TRUSTWORTHY;
}

export interface VerificationResult {
  decision: Decision; authentic: boolean; deviceIntegrityOk: boolean;
  checks: Check[]; schemaVersion: number | null; point: string | null;
  ts: number | null; nonce: string | null; device: DeviceInfo | null;
  signals: ResolvedSignal[];
}

export interface Session {
  pinnedKeySpkiHex: string; assurance: Assurance; bootState: string;
  deviceLocked: boolean; issuedAt: number;
  chainTrusted: boolean; keyboxRevoked: boolean; crossLevelReuse: boolean;
  strongboxChainMissing: boolean; devicePropMismatch: boolean;
  bootStateSpoofer: boolean; softwareAttested: boolean;
}
