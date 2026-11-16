//! v1 symmetric token crypto (Keystream.kt port). Confidentiality in transit
//! only — the scan path rejects v1 tokens; this decodes legacy ones.

use sha2::{Digest, Sha256};

const PHRASE: &str = "intel-verdict-token-key-v1"; // WIRE-CONSTANT (do NOT rebrand)

pub fn decrypt_bytes(cipher: &[u8]) -> Vec<u8> {
    let key = Sha256::digest(PHRASE.as_bytes());
    let mut out = cipher.to_vec();
    let mut block: u32 = 0;
    let mut off = 0usize;
    while off < out.len() {
        let mut ib = [0u8; 4];
        ib.copy_from_slice(&block.to_le_bytes());
        let ks = Sha256::digest(
            key.iter()
                .copied()
                .chain(ib.iter().copied())
                .collect::<Vec<u8>>(),
        );
        let take = std::cmp::min(32, out.len() - off);
        for i in 0..take {
            out[off + i] ^= ks[i];
        }
        off += 32;
        block += 1;
    }
    out
}

pub fn decrypt_hex(token_hex: &str) -> Result<String, String> {
    let trimmed = token_hex.trim();
    let cipher = hex::decode(trimmed).map_err(|_| "bad hex".to_string())?;
    Ok(String::from_utf8_lossy(&decrypt_bytes(&cipher)).into_owned())
}
