//! The Rust verifier suite: the same vectors the python/node/kotlin suites
//! pin — RFC 5869 HKDF, X25519 (dalek), the v2 ECIES KAT + tamper matrix,
//! policy/registry/signals truth tables, codec round-trips, the session
//! signing contract, and the rooted-Pixel real-device parity.

use deviceintelligence_verifier::attestation::hkdf::hkdf_sha256;
use deviceintelligence_verifier::codec;
use deviceintelligence_verifier::model::{decision, ResolvedSignal};
use deviceintelligence_verifier::policy::{Policy, Registry};
use deviceintelligence_verifier::tokens::keystream::decrypt_hex;
use deviceintelligence_verifier::tokens::lab_keys::SERVER_KEY;
use deviceintelligence_verifier::tokens::session_signer::SessionSigner;
use deviceintelligence_verifier::tokens::signals;
use deviceintelligence_verifier::tokens::token_crypto_v2;
use deviceintelligence_verifier::tokens::token_decoder::TokenDecoder;
use deviceintelligence_verifier::tokens::token_verifier::TokenVerifier;
use x509_parser::prelude::FromDer as _;

const SERVER_SCALAR_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const V2_TOKEN: &str = concat!(
    "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213",
    "1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a",
    "2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b"
);
const EXPECTED_V2: &str = "signed_content\n--BINDING\nSIG...\nCERT...";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../verifiers/fixtures");

fn scalar() -> [u8; 32] {
    hex::decode(SERVER_SCALAR_HEX).unwrap().try_into().unwrap()
}

fn v2_key() -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(scalar())
}

fn flip_at(token: &str, i: usize) -> String {
    let mut body: Vec<char> = token[2..].chars().collect();
    body[i] = if body[i] == '0' { '1' } else { '0' };
    format!("2:{}", body.iter().collect::<String>())
}

fn registry() -> Registry {
    Registry::bundled().unwrap()
}

fn policy() -> Policy {
    Policy::default()
}

// ---- HKDF (RFC 5869) ------------------------------------------------------

#[test]
fn hkdf_rfc5869_case1() {
    let okm = hkdf_sha256(
        &hex::decode("0b".repeat(22)).unwrap(),
        &hex::decode("000102030405060708090a0b0c").unwrap(),
        &hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
        42,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
}

#[test]
fn hkdf_rfc5869_case3_empty_salt_and_info() {
    let okm = hkdf_sha256(&hex::decode("0b".repeat(22)).unwrap(), &[], &[], 42).unwrap();
    assert_eq!(
        hex::encode(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8"
    );
}

#[test]
fn hkdf_rejects_output_over_255_blocks() {
    assert!(hkdf_sha256(&[1], &[], &[], 255 * 32 + 1).is_err());
}

// ---- X25519 (RFC 7748, via dalek) -----------------------------------------

#[test]
fn x25519_rfc7748_vectors() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let kat = |k: &str, u: &str| {
        let k_bytes: [u8; 32] = hex::decode(k).unwrap().try_into().unwrap();
        let u_bytes: [u8; 32] = hex::decode(u).unwrap().try_into().unwrap();
        StaticSecret::from(k_bytes)
            .diffie_hellman(&PublicKey::from(u_bytes))
            .to_bytes()
            .to_vec()
    };
    assert_eq!(
        kat(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        ),
        hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").unwrap()
    );
    assert_eq!(
        kat(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
        ),
        hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957").unwrap()
    );
}

// ---- v2 ECIES (KAT + tamper matrix) ---------------------------------------

#[test]
fn v2_decrypts_native_token() {
    let out = token_crypto_v2::decrypt(V2_TOKEN, &scalar()).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), EXPECTED_V2);
}

#[test]
fn v2_decrypts_empty_ciphertext() {
    let empty = concat!(
        "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011",
        "12131415161718191a1b9a7f7296f43354e241400ee7b8946c46"
    );
    assert!(token_crypto_v2::decrypt(empty, &scalar())
        .unwrap()
        .is_empty());
}

#[test]
fn v2_tamper_fails() {
    for i in [0usize, 2, 10, 70, 92] {
        let mut body: Vec<char> = V2_TOKEN[2..].chars().collect();
        body[i] = if body[i] == '0' { '1' } else { '0' };
        let tampered = format!("2:{}", body.iter().collect::<String>());
        assert!(
            token_crypto_v2::decrypt(&tampered, &scalar()).is_err(),
            "tamper at {i} must fail"
        );
    }
}

#[test]
fn v2_wrong_key_fails() {
    let other = "0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21";
    assert!(
        token_crypto_v2::decrypt(V2_TOKEN, &hex::decode(other).unwrap().try_into().unwrap())
            .is_err()
    );
}

#[test]
fn v2_malformed_inputs_fail() {
    assert!(token_crypto_v2::decrypt("deadbeefcafe", &scalar()).is_err());
    assert!(token_crypto_v2::decrypt("2:0203", &scalar()).is_err());
    assert!(token_crypto_v2::decrypt("2:abc", &scalar()).is_err());
    assert!(token_crypto_v2::decrypt("2:zzzz", &scalar()).is_err());
}

#[test]
fn v2_is_v2_discriminates() {
    assert!(token_crypto_v2::is_v2(V2_TOKEN));
    assert!(!token_crypto_v2::is_v2("deadbeefcafe"));
    assert!(!token_crypto_v2::is_v2(""));
    assert!(!token_crypto_v2::is_v2("2"));
}

// ---- Policy ----------------------------------------------------------------

#[test]
fn policy_critical_blocks() {
    assert!(policy().is_blocking(Some("INTEL_0001"), Some("CRITICAL"), None, None));
}

#[test]
fn policy_high_and_medium_do_not_block() {
    assert!(!policy().is_blocking(Some("INTEL_0019"), Some("HIGH"), None, None));
    assert!(!policy().is_blocking(Some("INTEL_0050"), Some("MEDIUM"), None, None));
}

#[test]
fn policy_allow_overrides_and_block_overrides() {
    let mut p = policy();
    p.allow = vec!["INTEL_0052".into()];
    assert!(!p.is_blocking(Some("INTEL_0052"), Some("CRITICAL"), None, None));
    p.allow = vec![];
    p.block = vec!["INTEL_0050".into()];
    assert!(p.is_blocking(Some("INTEL_0050"), Some("MEDIUM"), None, None));
}

#[test]
fn policy_case_insensitive_severity() {
    assert!(policy().is_blocking(None, Some("critical"), None, None));
    assert!(!policy().is_blocking(None, None, None, None));
}

#[test]
fn policy_rwx_paths() {
    assert!(
        policy().is_blocking(
            Some("INTEL_0052"),
            Some("CRITICAL"),
            Some("rwx_memory_mapping"),
            Some(3)
        ),
        "confirmed pool blocks"
    );
    assert!(
        policy().is_blocking(
            Some("INTEL_0052"),
            Some("CRITICAL"),
            Some("rwx_memory_mapping"),
            Some(0)
        ),
        "bare rwx under CRITICAL blocks by default"
    );
    let mut p = policy();
    p.observe_unconfirmed_rwx = true;
    assert!(
        !p.is_blocking(
            Some("INTEL_0052"),
            Some("CRITICAL"),
            Some("rwx_memory_mapping"),
            Some(0)
        ),
        "opted-in downgrade must not block"
    );
}

// ---- Registry + signals ----------------------------------------------------

#[test]
fn registry_bundled_loads_61_active_rows() {
    assert_eq!(registry().size(), 61);
}

#[test]
fn registry_resolves_intel_0042() {
    let reg = registry();
    let meta = reg.get(Some("INTEL_0042")).unwrap();
    assert_eq!(meta.detector, "native_integrity");
    assert_eq!(meta.kind, "text_integrity_divergence");
    assert_eq!(meta.severity, "CRITICAL");
}

#[test]
fn registry_retired_codes_are_absent() {
    assert!(registry().get(Some("INTEL_0020")).is_none());
    assert!(registry().get(Some("INTEL_0039")).is_none());
}

fn signals_fixture(doc: &str) -> Vec<ResolvedSignal> {
    let parsed: serde_json::Value = serde_json::from_str(doc).unwrap();
    signals::resolve(&parsed, &registry(), &policy())
}

#[test]
fn signals_resolve_enrichment_attributes() {
    let doc = r#"{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}"#;
    let sig = &signals_fixture(doc)[0];
    assert_eq!(sig.attr("module_id"), Some("evilmod"));
    assert_eq!(sig.attr("needed"), Some("liblog.so,libc.so"));
    assert_eq!(sig.attr("links_hook_lib"), Some("libdobby.so"));
    assert_eq!(
        sig.attr("path"),
        Some("/data/adb/modules/evilmod/zygisk/arm64-v8a.so")
    );
}

#[test]
fn signals_unknown_falls_back_to_question_marks() {
    let sig = &signals_fixture(r#"{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}"#)[0];
    assert_eq!(sig.detector, "?");
    assert_eq!(sig.kind, "?");
    assert_eq!(sig.severity, "CRITICAL");
}

#[test]
fn signals_legacy_sig_prefix_bridges() {
    let sig = &signals_fixture(r#"{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}"#)[0];
    assert_eq!(sig.id, "INTEL_0052");
}

#[test]
fn signals_definitive_hooks_correlate() {
    let doc = r#"{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059","severity":"HIGH","detail":"lie. hooked_symbol=faccessat path=/system/bin/sh"},{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}"#;
    let hooks = signals::definitive_hooks(&signals_fixture(doc));
    assert_eq!(hooks, vec!["faccessat"]);
}

// ---- Session signer --------------------------------------------------------

fn fixture_session() -> serde_json::Value {
    serde_json::json!({
        "pinnedKeySpkiHex": "30591301deadbeef",
        "assurance": "STRONGBOX",
        "bootState": "Verified",
        "deviceLocked": true,
        "issuedAt": 1_787_220_000i64,
        "chainTrusted": false,
        "keyboxRevoked": false,
        "crossLevelReuse": false,
        "strongboxChainMissing": false,
        "devicePropMismatch": false,
        "bootStateSpoofer": false,
        "softwareAttested": false,
    })
}

#[test]
fn session_signer_round_trips() {
    let signer = SessionSigner::new(SERVER_KEY, || 1_787_220_000 + 100);
    let opened = signer.open(&signer.issue(&fixture_session())).unwrap();
    assert_eq!(opened["assurance"], "STRONGBOX");
    assert_eq!(opened["deviceLocked"], true);
    assert_eq!(opened["issuedAt"], 1_787_220_000i64);
}

#[test]
fn session_signer_rejects_expired() {
    let signer = SessionSigner::new(SERVER_KEY, || 1_787_220_000);
    let late = SessionSigner::new(SERVER_KEY, || {
        1_787_220_000 + SessionSigner::DEFAULT_MAX_AGE_SECONDS + 1
    });
    assert!(late.open(&signer.issue(&fixture_session())).is_none());
}

#[test]
fn session_signer_rejects_tampered_payload() {
    let signer = SessionSigner::new(SERVER_KEY, || 1_787_220_000 + 100);
    let id = signer.issue(&fixture_session());
    let (payload, mac) = id.split_once('.').unwrap();
    let last = payload.chars().last().unwrap();
    let flipped = if last == 'A' { 'B' } else { 'A' };
    let forged = format!("{}{}.{}", &payload[..payload.len() - 1], flipped, mac);
    assert!(signer.open(&forged).is_none());
}

#[test]
fn session_signer_rejects_wrong_key() {
    let signer = SessionSigner::new(SERVER_KEY, || 1_787_220_000 + 100);
    let forged = SessionSigner::new(b"different-key", || 1_787_220_000 + 100);
    assert!(forged.open(&signer.issue(&fixture_session())).is_none());
}

#[test]
fn session_signer_rejects_malformed() {
    let signer = SessionSigner::new(SERVER_KEY, || 1_787_220_000 + 100);
    assert!(signer.open("not-a-session").is_none());
}

// ---- Codec -----------------------------------------------------------------

#[test]
fn codec_decodes_python_backend_fixture() {
    let raw = std::fs::read_to_string(format!("{FIXTURES}/py-session.json")).unwrap();
    let s = codec::decode(&raw).unwrap();
    assert_eq!(s["assurance"], "STRONGBOX");
    assert_eq!(s["bootState"], "SelfSigned");
    assert_eq!(s["bootStateSpoofer"], true);
    assert_eq!(s["deviceLocked"], true);
    assert_eq!(s["chainTrusted"], true);
    assert_eq!(s["keyboxRevoked"], false);
    assert_eq!(s["osPatchLevel"], 202604);
    assert_eq!(s["fingerprint"]["securityLevel"], "L1");
}

#[test]
fn codec_rejects_malformed_document() {
    assert!(codec::decode(r#"{"assurance":"TEE"}"#).is_err());
}

// ---- Keystream (v1) + token decoder ---------------------------------------

#[test]
fn token_decoder_decodes_real_challenge_fixture() {
    let raw = std::fs::read_to_string(format!("{FIXTURES}/pixel-challenge.token")).unwrap();
    let decoded = TokenDecoder::new(registry(), policy()).decode(raw.trim());
    // The pixel challenge token is the only fixture that must decode AND bind.
    assert!(decoded.is_ok(), "decode failed: {decoded:?}");
    let d = decoded.unwrap();
    assert_eq!(d["schemaVersion"], 3);
    assert_eq!(d["hasBinding"], true);
}

// ---- Pixel real-device parity ----------------------------------------------

#[test]
fn pixel_real_token_parity_compromised() {
    let token = std::fs::read_to_string(format!("{FIXTURES}/pixel-token.hex"))
        .unwrap()
        .trim()
        .to_string();
    let nonce = std::fs::read_to_string(format!("{FIXTURES}/pixel-nonce.hex"))
        .unwrap()
        .trim()
        .to_string();
    let verifier = TokenVerifier::bundled().unwrap();
    let res = verifier.verify(&token, &nonce);

    for c in &res.checks {
        eprintln!(
            "DBG {} {} {} {}",
            c.kind,
            if c.ok { "PASS" } else { "FAIL" },
            c.name,
            c.detail
        );
    }
    assert!(res.authentic);
    assert!(!res.device_integrity_ok);
    assert_eq!(res.decision, decision::COMPROMISED);

    // RegistryVersion-1 capture: the pre-reshuffle code resolves to whatever
    // row owns that number today.
    let sig0 = res
        .signals
        .iter()
        .find(|s| s.id == "INTEL_0000")
        .expect("INTEL_0000 missing");
    assert!(sig0.blocking);

    let by_name: std::collections::HashMap<&str, bool> =
        res.checks.iter().map(|c| (c.name.as_str(), c.ok)).collect();
    assert!(by_name["binding present"]);
    assert!(by_name["nonce matches issued"]);
    assert!(by_name["chain -> pinned Google root"]);
    assert!(by_name["signature over verdict"]);
    assert!(!by_name["verified boot state = Verified"]);
}

#[test]
fn debug_parse_chain_errors() {
    use deviceintelligence_verifier::attestation::chain_verifier as cv;
    use deviceintelligence_verifier::tokens::keystream::decrypt_hex;
    let token = std::fs::read_to_string(format!("{FIXTURES}/pixel-token.hex")).unwrap();
    let text = decrypt_hex(token.trim()).unwrap();
    let sep = text.find("\n--BINDING\n").unwrap();
    let binding = &text[sep + 11..];
    for line in binding.split('\n') {
        if let Some(cert_hex) = line.strip_prefix("CERT\u{1F}") {
            let der = hex::decode(cert_hex).unwrap();
            match x509_parser::prelude::X509Certificate::from_der(&der) {
                Ok(_) => println!("PARSE OK len={}", der.len()),
                Err(e) => println!("PARSE ERR: {e}"),
            }
        }
    }
}
