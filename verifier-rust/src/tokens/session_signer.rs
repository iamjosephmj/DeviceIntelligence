//! Stateless HMAC-signed session tokens (SessionSigner.kt port). The token is
//! "<payload-b64url>.<mac-b64url>"; tampering with either half fails.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

pub struct SessionSigner {
    key: Vec<u8>,
    max_age_seconds: i64,
    now: Box<dyn Fn() -> i64>,
}

impl SessionSigner {
    pub const DEFAULT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
}

impl SessionSigner {
    pub fn new(key: &[u8], now: impl Fn() -> i64 + 'static) -> Self {
        SessionSigner {
            key: key.to_vec(),
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            now: Box::new(now),
        }
    }

    pub fn issue(&self, session: &serde_json::Value) -> String {
        let payload = serde_json::json!({
            "pinnedKey": session["pinnedKeySpkiHex"],
            "assurance": session["assurance"],
            "boot": session["bootState"],
            "locked": session["deviceLocked"],
            "issuedAt": session["issuedAt"],
            "chainTrusted": session["chainTrusted"],
            "kbRevoked": session["keyboxRevoked"],
            "xlReuse": session["crossLevelReuse"],
            "sbMissing": session["strongboxChainMissing"],
            "propMismatch": session["devicePropMismatch"],
            "bootSpoofer": session["bootStateSpoofer"],
            "swAttest": session["softwareAttested"],
        })
        .to_string();
        let b64 = |b: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        format!(
            "{}.{}",
            b64(payload.as_bytes()),
            b64(&self.mac(payload.as_bytes()))
        )
    }

    /// The carried session facts, or None on tamper / wrong key / expiry /
    /// malformed.
    pub fn open(&self, session_id: &str) -> Option<serde_json::Value> {
        let dot = session_id.find('.')?;
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&session_id[..dot])
            .ok()?;
        let mac = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&session_id[dot + 1..])
            .ok()?;
        if !self.constant_time_eq(&self.mac(&payload), &mac) {
            return None;
        }
        let o: serde_json::Value = serde_json::from_slice(&payload).ok()?;
        let issued_at = o["issuedAt"].as_i64()?;
        if issued_at <= 0 || (self.now)() - issued_at > self.max_age_seconds {
            return None;
        }
        Some(serde_json::json!({
            "pinnedKeySpkiHex": o["pinnedKey"],
            "assurance": o["assurance"],
            "bootState": o["boot"],
            "deviceLocked": o["locked"] == true,
            "issuedAt": issued_at,
            "chainTrusted": o["chainTrusted"] == true,
            "keyboxRevoked": o["kbRevoked"] == true,
            "crossLevelReuse": o["xlReuse"] == true,
            "strongboxChainMissing": o["sbMissing"] == true,
            "devicePropMismatch": o["propMismatch"] == true,
            "bootStateSpoofer": o["bootSpoofer"] == true,
            "softwareAttested": o["swAttest"] == true,
        }))
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut h = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        h.update(data);
        h.finalize().into_bytes().to_vec()
    }

    fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}
