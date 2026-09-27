//! v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 discriminator.
//! Wire: "2:" + hex(version || epoch || eph_pub(32) || nonce(12) || ct || tag).
//! Every corruption fails the GCM tag — a tampered token never decrypts.

use crate::attestation::hkdf::hkdf_sha256;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PREFIX: &str = "2:";
const INFO_PREFIX: &[u8] = b"intel-token-v2";
const HEADER: usize = 1 + 1 + 32 + 12;
const TAG: usize = 16;

pub fn is_v2(token: &str) -> bool {
    token.starts_with(PREFIX)
}

/// Decrypt a "2:" token. [server_scalar] is the raw 32-byte X25519 private
/// scalar. Errors on tamper (GCM auth), malformed input, and trivial
/// (all-zero) shared secrets — never returns plaintext on any corruption.
pub fn decrypt(token_v2: &str, server_scalar: &[u8; 32]) -> Result<Vec<u8>, String> {
    if !token_v2.starts_with(PREFIX) {
        return Err("not a v2 token".into());
    }
    let body = &token_v2[PREFIX.len()..];
    if body.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let p = hex::decode(body).map_err(|_| "bad hex char".to_string())?;
    if p.len() < HEADER + TAG {
        return Err("v2 token too short".into());
    }

    let version = p[0];
    let epoch = p[1];
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&p[2..34]);
    eph[31] &= 0x7f; // RFC 7748: the ignored high bit
    let nonce: [u8; 12] = p[34..46].try_into().expect("nonce is 12 bytes");
    let ct_and_tag = &p[HEADER..];

    let secret = StaticSecret::from(*server_scalar);
    let public = PublicKey::from(eph);
    let shared = secret.diffie_hellman(&public);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err("all-zero shared secret".into());
    }
    let key = hkdf_sha256(
        shared.as_bytes(),
        &nonce,
        &[INFO_PREFIX, &[epoch]].concat(),
        32,
    )?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut full_aad = vec![version, epoch];
    full_aad.extend_from_slice(&eph);
    let payload = Payload {
        msg: ct_and_tag,
        aad: &full_aad,
    };
    cipher
        .decrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| "gcm auth failed".into())
}
