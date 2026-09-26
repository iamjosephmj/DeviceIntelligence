// The flat public surface of the TypeScript verifier — the same shape the
// Kotlin artifact and the Python package expose. Feature packages remain
// importable directly (verifier-node/dist/tokens/token_verifier.js, …) for
// consumers that want a narrower surface.
export * from "./model.js";

export { TokenVerifier } from "./tokens/token_verifier.js";
export { TokenDecoder, BINDING_SEP } from "./tokens/token_decoder.js";
export { SessionSigner, DEFAULT_MAX_AGE_SECONDS } from "./tokens/session_signer.js";
export { decryptV2, isV2 } from "./tokens/token_crypto.js";
export { decryptHex, decryptBytes } from "./tokens/keystream.js";
export { resolve as resolveSignals, device as signalsDevice } from "./tokens/signals.js";

export { ScanVerifier, bootStateSpoofer } from "./scan/scan_verifier.js";
export { decode, encode } from "./scan/codec.js";

export { challenge as attestationChallenge, fields as attestationFields } from "./attestation/attestation.js";
export { parseChain, verifyToPinnedRoot } from "./attestation/chain_verifier.js";
export { AttestationCrl } from "./attestation/crl.js";
export { parse as parsePinnedRoots, pinnedRootsDefault } from "./attestation/pinned_roots.js";
export { sha256 as hkdfSha256 } from "./attestation/hkdf.js";

export { Policy, defaultPolicy, isBlocking } from "./policy/policy.js";
export { SignalRegistry } from "./policy/registry.js";
export { LicenseChecker } from "./model.js";
