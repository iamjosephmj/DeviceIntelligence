//! The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts.
//! Layered like every port: AUTH failures => REJECT, INTEGRITY failures =>
//! COMPROMISED, blocking signals => COMPROMISED, else TRUSTWORTHY.

use super::signals;
use crate::attestation::chain_verifier::{parse_chain, verify_to_pinned_root};
use crate::attestation::pinned_roots::{default as default_pinned_roots, PinnedRoot};
use crate::model::{check_kind, decision, Check, VerificationResult};
use crate::policy::{Policy, Registry};

pub const BINDING_SEP: &str = "\n--BINDING\n";
pub const FS: &str = "\u{1F}";

pub struct TokenVerifier {
    registry: Registry,
    policy: Policy,
    pinned_roots: Vec<PinnedRoot>,
}

// The check ledger: gates record under their layer; the two layer verdicts
// fall out of the ledger.
struct Checks {
    all: Vec<Check>,
}

impl Checks {
    fn new() -> Self {
        Checks { all: Vec::new() }
    }

    fn auth(&mut self, name: &str, ok: bool, detail: &str) -> bool {
        self.all.push(Check {
            name: name.to_string(),
            ok,
            detail: detail.to_string(),
            kind: check_kind::AUTH.to_string(),
        });
        ok
    }

    fn integ(&mut self, name: &str, ok: bool, detail: &str) -> bool {
        self.all.push(Check {
            name: name.to_string(),
            ok,
            detail: detail.to_string(),
            kind: check_kind::INTEGRITY.to_string(),
        });
        ok
    }

    fn device_integrity_ok(&self) -> bool {
        self.all
            .iter()
            .filter(|c| c.kind == check_kind::INTEGRITY)
            .all(|c| c.ok)
    }

    fn to_list(&self) -> Vec<Check> {
        self.all.clone()
    }
}

impl TokenVerifier {
    pub fn new(registry: Registry, policy: Policy, pinned_roots: Vec<PinnedRoot>) -> Self {
        TokenVerifier {
            registry,
            policy,
            pinned_roots,
        }
    }

    pub fn bundled() -> Result<Self, String> {
        Ok(TokenVerifier::new(
            Registry::bundled()?,
            Policy::default(),
            default_pinned_roots()?,
        ))
    }

    pub fn verify(&self, token_hex: &str, issued_nonce: &str) -> VerificationResult {
        let mut checks = Checks::new();

        let text = match crate::tokens::keystream::decrypt_hex(token_hex) {
            Ok(t) => t,
            Err(_) => return self.reject_result(&checks, &serde_json::Value::Null),
        };
        let sep = text.find(BINDING_SEP);
        let has_binding = sep.is_some();
        let signed = match sep {
            Some(i) => text[..i].to_string(),
            None => text.clone(),
        };
        let binding = match sep {
            Some(i) => text[i + BINDING_SEP.len()..].to_string(),
            None => String::new(),
        };
        let doc: serde_json::Value =
            serde_json::from_str(&signed).unwrap_or(serde_json::Value::Null);

        if !checks.auth(
            "binding present",
            has_binding,
            if has_binding {
                ""
            } else {
                "unbound/legacy token"
            },
        ) {
            return self.reject_result(&checks, &doc);
        }
        if !doc.is_object() || doc.as_object().map(|o| o.len()).unwrap_or(0) == 0 {
            checks.auth(
                "signed content is JSON",
                false,
                "unparseable signed_content",
            );
            return self.reject_result(&checks, &doc);
        }

        let token_nonce = doc["nonce"].as_str().unwrap_or("");
        checks.auth("nonce matches issued", token_nonce == issued_nonce, "");

        let (sig_hex, certs_hex) = parse_binding(&binding);
        if !checks.auth(
            "chain + signature present",
            !sig_hex.is_empty() && !certs_hex.is_empty(),
            "",
        ) {
            return self.reject_result(&checks, &doc);
        }

        let chain = match parse_chain(&certs_hex) {
            Ok(c) if !c.is_empty() => c,
            Err(e) => {
                checks.auth(
                    "chain parses",
                    false,
                    &format!("could not parse cert chain: {e}"),
                );
                return self.reject_result(&checks, &doc);
            }
            _ => {
                checks.auth("chain parses", false, "could not parse cert chain");
                return self.reject_result(&checks, &doc);
            }
        };
        let leaf = &chain[0];

        match verify_to_pinned_root(&chain, &self.pinned_roots) {
            Ok(root) => checks.auth("chain -> pinned Google root", true, &root_fp_hint(&root.fp)),
            Err(e) => checks.auth("chain -> pinned Google root", false, &e),
        };

        let chal = crate::attestation::attestation::challenge(&leaf.der).ok();
        let chal_ok = chal
            .as_ref()
            .map(|c| hex::encode(c) == issued_nonce.to_lowercase())
            .unwrap_or(false);
        checks.auth("attestation challenge == nonce", chal_ok, "");

        let sig_ok = (|| {
            let sig = hex::decode(&sig_hex).ok()?;
            let spki = leaf_spki_der(leaf);
            crate::attestation::chain_verifier::verify_signed_data(&spki, signed.as_bytes(), &sig)
                .then_some(true)
        })()
        .unwrap_or(false);
        checks.auth(
            "signature over verdict",
            sig_ok,
            if sig_ok { "" } else { "ECDSA verify failed" },
        );

        // Device-integrity layer — the TEE's own attestation fields.
        let fields = crate::attestation::attestation::fields(&leaf.der).ok();
        let sec_ok = fields
            .as_ref()
            .map(|f| matches!(f.security_level, Some(1) | Some(2)))
            .unwrap_or(false);
        let boot_ok = fields
            .as_ref()
            .map(|f| f.verified_boot_state == Some(0))
            .unwrap_or(false);
        let lock_ok = fields
            .as_ref()
            .map(|f| f.device_locked == Some(true))
            .unwrap_or(false);
        checks.integ(
            "hardware security level >= TEE",
            sec_ok,
            &fields
                .as_ref()
                .map(|f| crate::attestation::attestation::security_level_name(f.security_level))
                .unwrap_or_else(|| "parse error".into()),
        );
        checks.integ(
            "verified boot state = Verified",
            boot_ok,
            &fields
                .as_ref()
                .map(|f| crate::attestation::attestation::boot_state_name(f.verified_boot_state))
                .unwrap_or_else(|| "parse error".into()),
        );
        checks.integ(
            "device locked",
            lock_ok,
            &fields
                .as_ref()
                .map(|f| f.device_locked.map(|b| b.to_string()).unwrap_or_default())
                .unwrap_or_else(|| "parse error".into()),
        );

        self.result(&checks, &doc)
    }

    fn reject_result(&self, checks: &Checks, doc: &serde_json::Value) -> VerificationResult {
        self.finish(checks, doc, false)
    }

    fn result(&self, checks: &Checks, doc: &serde_json::Value) -> VerificationResult {
        self.finish(checks, doc, true)
    }

    fn finish(
        &self,
        checks: &Checks,
        doc: &serde_json::Value,
        authentic: bool,
    ) -> VerificationResult {
        let device_ok = checks.device_integrity_ok();
        let signals = signals::resolve(doc, &self.registry, &self.policy);
        let blocking = signals.iter().any(|s| s.blocking);
        let decision = if !authentic {
            decision::REJECT
        } else if !device_ok || blocking {
            decision::COMPROMISED
        } else {
            decision::TRUSTWORTHY
        };
        VerificationResult {
            decision: decision.to_string(),
            authentic,
            device_integrity_ok: device_ok,
            checks: checks.to_list(),
            schema_version: doc["schemaVersion"].as_i64(),
            point: doc["point"].as_str().map(|s| s.to_string()),
            ts: doc["ts"].as_i64(),
            nonce: doc["nonce"].as_str().map(|s| s.to_string()),
            device: signals::device(doc),
            signals,
        }
    }
}

fn root_fp_hint(fp: &str) -> String {
    format!("sha256:{fp}")
}

fn leaf_spki_der(leaf: &crate::attestation::chain_verifier::ChainCert) -> Vec<u8> {
    leaf.spki_der.clone()
}

fn parse_binding(binding: &str) -> (String, Vec<String>) {
    let mut sig_hex = String::new();
    let mut certs_hex = Vec::new();
    for line in binding.split('\n') {
        if let Some(rest) = line.strip_prefix("SIG\u{1F}") {
            sig_hex = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("CERT\u{1F}") {
            certs_hex.push(rest.to_string());
        }
    }
    (sig_hex, certs_hex)
}
