//! Loads the backend X25519 private half (ServerKey.kt port): the raw 32-byte
//! scalar the X25519 crate consumes. Accepts PEM or raw DER PKCS#8; a
//! truncated tail-32 fallback mirrors the Kotlin no-XDH path for exotic
//! encodings.

pub fn from_bytes(data: &[u8]) -> [u8; 32] {
    if let Some(der) = pem_der_body(data) {
        return from_pkcs8(&der);
    }
    from_pkcs8(data)
}

pub fn from_file(path: &str) -> [u8; 32] {
    from_bytes(&std::fs::read(path).unwrap_or_else(|e| panic!("server key unreadable: {e}")))
}

fn from_pkcs8(der: &[u8]) -> [u8; 32] {
    if der.len() < 32 {
        panic!("PKCS#8 X25519 key too short: {} bytes", der.len());
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&der[der.len() - 32..]);
    scalar
}

fn pem_der_body(data: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let start = text.find("-----BEGIN")?;
    let begin_end = text[start..].find("-----")? + start + 5;
    let end_rel = text[begin_end..].find("-----END")? + begin_end;
    let body: String = text[begin_end..end_rel]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(&body).ok()
}
