//! Token attestation chain validation (ChainVerifier.kt port). Signature-only:
//! each cert signed by the next, and the chain top must terminate in a pinned
//! Google root (by SHA-256 of the DER, or by key verification — Pixel chains
//! mix EC keyboxes with RSA Google intermediates).

use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::pinned_roots::PinnedRoot;
use crate::text::der::{sequence_elements, tlv_list};

/// The full tbsCertificate TLV (what the issuer signs), the DER, the
/// signature BIT STRING content (unused-bits octet stripped), and the
/// subjectPublicKeyInfo DER of each chain certificate.
#[derive(Clone, Debug)]
pub struct ChainCert {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub fp: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn parse_chain(certs_hex: &[String]) -> Result<Vec<ChainCert>, String> {
    certs_hex
        .iter()
        .map(|h| {
            let der = hex::decode(h).map_err(|_| "bad cert hex".to_string())?;
            // The Certificate SEQUENCE wraps exactly three elements:
            // [0] tbsCertificate, [1] signatureAlgorithm, [2] signatureValue.
            let elems = sequence_elements(&der).map_err(|e| e.to_string())?;
            if elems.len() < 3 {
                return Err("certificate has fewer than 3 elements".into());
            }
            let tbs_tlv = &elems[0];
            // The issuer signs the complete tbsCertificate TLV, length
            // header included — keep the raw encoding byte-for-byte.
            let tbs = tbs_tlv.raw.clone();
            // signatureValue BIT STRING content starts with an unused-bits
            // octet (always 0 for whole-byte signature values).
            let signature = elems[2].value[1..].to_vec();
            // subjectPublicKeyInfo lives inside the tbsCertificate: the
            // element right before the [3] extensions wrapper (index 6 on
            // v3 certs, last on version-less v1 certs).
            let tbs_elems = tlv_list(&tbs_tlv.value).map_err(|e| e.to_string())?;
            let ext_idx = tbs_elems.iter().position(|e| e.tag.first() == Some(&0xa3));
            let spki_idx = match ext_idx {
                Some(i) if i > 0 => i - 1,
                _ => tbs_elems.len().saturating_sub(1),
            };
            let spki_der = tbs_elems[spki_idx].raw.clone();
            Ok(ChainCert {
                fp: hex::encode(Sha256::digest(&der)),
                der,
                tbs,
                signature,
                spki_der,
            })
        })
        .collect()
}

/// Verify [sig_der] over [message] with the key in [spki_der]: ECDSA P-256
/// first (the keybox leaf), then RSA PKCS#1 v1.5 with SHA-256/384/512 (Google
/// intermediates and roots).
pub fn verify_signed_data(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    ec_p256_verify(spki_der, message, sig_der)
        || ec_p384_verify(spki_der, message, sig_der)
        || rsa_pkcs1_verify(spki_der, message, sig_der)
}

/// ECDSA over P-256: the keybox leaf and Pixel hardware intermediates.
fn ec_p256_verify(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_der(sig_der) else {
        return false;
    };
    // The crate hashes [message] with SHA-256 internally, matching the spec.
    vk.verify(message, &sig).is_ok()
}

/// ECDSA over P-384: the Google hardware-attestation EC intermediate. The
/// certificate's signatureAlgorithm picks the digest (SHA-256 or SHA-384 are
/// both seen in the wild), so verify against each precomputed one.
fn ec_p384_verify(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Ok(sig) = p384::ecdsa::Signature::from_der(sig_der) else {
        return false;
    };
    [
        Sha256::digest(message).to_vec(),
        Sha384::digest(message).to_vec(),
    ]
    .iter()
    .any(|digest| vk.verify_prehash(digest.as_slice(), &sig).is_ok())
}

fn rsa_pkcs1_verify(spki_der: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(spki_der) else {
        return false;
    };
    // The rsa crate verifies over the precomputed digest; try each hash the
    // chain authority is known to use.
    let attempts = [
        (
            Sha256::digest(message).to_vec(),
            Pkcs1v15Sign::new::<Sha256>(),
        ),
        (
            Sha384::digest(message).to_vec(),
            Pkcs1v15Sign::new::<Sha384>(),
        ),
        (
            Sha512::digest(message).to_vec(),
            Pkcs1v15Sign::new::<Sha512>(),
        ),
    ];
    attempts
        .into_iter()
        .any(|(digest, scheme)| key.verify(scheme, &digest, sig_der).is_ok())
}

/// Returns the pinned root the chain terminates in, or an error when no
/// pinned root accepts it.
pub fn verify_to_pinned_root(
    chain: &[ChainCert],
    pinned: &[PinnedRoot],
) -> Result<PinnedRoot, String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    for pair in chain.windows(2) {
        let (cert, issuer) = (&pair[0], &pair[1]);
        if !verify_signed_data(&issuer.spki_der, &cert.tbs, &cert.signature) {
            return Err("pairwise signature mismatch".into());
        }
    }
    let top = chain.last().expect("chain non-empty");
    for root in pinned {
        if top.fp == root.fp {
            return Ok(root.clone());
        }
        if verify_signed_data(&root.spki_der, &top.tbs, &top.signature) {
            return Ok(root.clone());
        }
    }
    Err("chain top does not chain to a pinned Google root".into())
}
