//! HKDF-SHA256 (RFC 5869) — extract-and-expand on HMAC/SHA-256.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_OUT: usize = 255 * 32;

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if length > MAX_OUT {
        return Err(format!("HKDF outLen out of range: {length}"));
    }
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };

    let mut extractor = HmacSha256::new_from_slice(salt).expect("hmac accepts any key length");
    extractor.update(ikm);
    let prk = extractor.finalize().into_bytes();

    let mut out = Vec::with_capacity(length);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut h = HmacSha256::new_from_slice(&prk).expect("hmac accepts any key length");
        h.update(&prev);
        h.update(info);
        h.update(&[counter]);
        prev = h.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.checked_add(1).ok_or("HKDF counter overflow")?;
    }
    out.truncate(length);
    Ok(out)
}
