//! DeviceIntelligence backend token verifier (Rust port of the Kotlin/JVM
//! verifier). Packaged by feature, mirroring the kotlin/python/node layouts:
//! `tokens` (token verify flow), `attestation` (chain + KeyDescription walk,
//! pinned roots, CRL, HKDF), `policy` (blocking policy + signal registry),
//! `text` (DER walker), `codec` (ScanSession JSON round-trip).

pub mod attestation;
pub mod codec;
pub mod model;
pub mod policy;
pub mod text;
pub mod tokens;

pub use codec::{decode, encode};
pub use model::decision;
pub use model::{Check, ResolvedSignal, VerificationResult};
pub use policy::{Policy, Registry};
pub use tokens::token_decoder::TokenDecoder;
pub use tokens::token_verifier::TokenVerifier;
