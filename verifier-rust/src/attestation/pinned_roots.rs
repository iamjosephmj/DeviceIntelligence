//! The pinned Google hardware-attestation roots (PinnedRoots.kt port).
//! Bundled file: base64 DER, one root per line, '#' comments allowed.

use base64::Engine as _;
use sha2::Digest as _;
use x509_parser::prelude::FromDer as _;

#[derive(Clone, Debug)]
pub struct PinnedRoot {
    pub fp: String,
    pub der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

pub fn parse(text: &str) -> Result<Vec<PinnedRoot>, String> {
    let mut roots = Vec::new();
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(line)
            .map_err(|e| format!("bad base64 pinned root: {e}"))?;
        let (_, cert) =
            x509_parser::prelude::X509Certificate::from_der(&der).map_err(|e| e.to_string())?;
        roots.push(PinnedRoot {
            fp: hex::encode(sha2::Sha256::digest(&der)),
            spki_der: cert.public_key().raw.to_vec(),
            der,
        });
    }
    Ok(roots)
}

pub fn default() -> Result<Vec<PinnedRoot>, String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/resources/pinned-roots.txt");
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("pinned roots unreadable: {e}"))?;
    parse(&text)
}
