//! Decrypts a token and returns its document WITHOUT verifying
//! (TokenDecoder.kt port).

use super::keystream::decrypt_hex;
use super::signals;
use crate::policy::policy::Policy;
use crate::policy::registry::Registry;
use serde_json::Value;

pub const BINDING_SEP: &str = "\n--BINDING\n";

pub struct TokenDecoder {
    registry: Registry,
    policy: Policy,
}

impl TokenDecoder {
    pub fn new(registry: Registry, policy: Policy) -> Self {
        TokenDecoder { registry, policy }
    }

    pub fn decode(&self, token_hex: &str) -> Result<Value, String> {
        let text = decrypt_hex(token_hex)?;
        let idx = text.find(BINDING_SEP);
        let signed = match idx {
            Some(i) => &text[..i],
            None => &text[..],
        };
        let doc: Value = serde_json::from_str(signed).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "schemaVersion": doc["schemaVersion"],
            "point": doc["point"],
            "ts": doc["ts"],
            "nonce": doc["nonce"],
            "device": signals::device(&doc),
            "signals": signals::resolve(&doc, &self.registry, &self.policy),
            "hasBinding": idx.is_some(),
        }))
    }
}
