//! Attestation-key revocation list (the weekly-baked encrypted crl.bin asset,
//! already decrypted by the caller). Serial matching normalizes case, an
//! optional 0x prefix, and leading zeros away — "0" stays "0".

use std::collections::HashSet;

#[derive(Clone, Debug, Default)]
pub struct AttestationCrl {
    revoked: HashSet<String>,
}

pub fn normalize(serial_hex: &str) -> String {
    let mut s = serial_hex.trim().to_uppercase();
    if let Some(stripped) = s.strip_prefix("0X") {
        s = stripped.to_string();
    }
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_string()
    }
}

impl AttestationCrl {
    pub fn parse(text: &str) -> Self {
        let revoked = text
            .split('\n')
            .map(|line| normalize(line.split('#').next().unwrap_or("")))
            .filter(|n| !n.is_empty())
            .collect();
        AttestationCrl { revoked }
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("crl unreadable: {e}"))?;
        Ok(Self::parse(&text))
    }

    pub fn revoked(&self, serial_hex: &str) -> bool {
        self.revoked.contains(&normalize(serial_hex))
    }

    pub fn size(&self) -> usize {
        self.revoked.len()
    }
}
