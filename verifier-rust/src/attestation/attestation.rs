//! Android Key Attestation extension reader (Attestation.kt port), on the
//! minimal DER walker. KeyDescription element indexes (spec §8): [1]
//! attestationSecurityLevel (ENUMERATED), [4] attestationChallenge (OCTET
//! STRING), [6] softwareEnforced, [7] teeEnforced — [7] preferred.
//! RootOfTrust entry tag: BF 85 40.

use crate::text::der::{read_tlv, sequence_elements, tlv_list};

pub const OID_HEX: &str = "2b06010401d679020111"; // 1.3.6.1.4.1.11129.2.1.17
const ROOT_OF_TRUST_TAG: &[u8] = &[0xBF, 0x85, 0x40];

pub const SECURITY_LEVEL_NAMES: [(i64, &str); 3] =
    [(0, "Software"), (1, "TrustedEnvironment"), (2, "StrongBox")];
pub const BOOT_STATE_NAMES: [(i64, &str); 4] = [
    (0, "Verified"),
    (1, "SelfSigned"),
    (2, "Unverified"),
    (3, "Failed"),
];

#[derive(Clone, Debug, Default)]
pub struct AttestationFields {
    pub security_level: Option<i64>,
    pub verified_boot_state: Option<i64>,
    pub device_locked: Option<bool>,
}

pub fn security_level_name(level: Option<i64>) -> String {
    match level {
        None => "?".into(),
        Some(l) => SECURITY_LEVEL_NAMES
            .iter()
            .find(|(k, _)| *k == l)
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| l.to_string()),
    }
}

pub fn boot_state_name(state: Option<i64>) -> String {
    match state {
        None => "?".into(),
        Some(s) => BOOT_STATE_NAMES
            .iter()
            .find(|(k, _)| *k == s)
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| s.to_string()),
    }
}

// The KeyDescription DER: walk Certificate > tbsCertificate > [3] extensions,
// find our OID (by its DER bytes), return the extnValue OCTET STRING content.
pub fn key_description_der(leaf_der: &[u8]) -> Result<Vec<u8>, String> {
    let oid_bytes = hex::decode(OID_HEX).map_err(|_| "bad OID hex".to_string())?;
    let cert_elems = sequence_elements(leaf_der)?;
    // Element [0] of Certificate IS the tbsCertificate SEQUENCE — the [3]
    // extensions tag lives among ITS elements, one level deeper.
    let tbs = cert_elems.first().ok_or("empty certificate DER")?;
    let tbs_elems = tlv_list(&tbs.value)?;
    for e in &tbs_elems {
        if e.tag.first() != Some(&0xa3) {
            continue; // [3] extensions, explicit
        }
        let (ext_seq, _) = read_tlv(&e.value, 0)?;
        for ext in tlv_list(&ext_seq.value)? {
            let parts = tlv_list(&ext.value)?;
            if let Some(oid) = parts.first() {
                if oid.value == oid_bytes {
                    return Ok(parts.last().map(|p| p.value.clone()).unwrap_or_default());
                }
            }
        }
    }
    Err("no Android attestation extension on leaf".into())
}

pub fn challenge(leaf_der: &[u8]) -> Result<Vec<u8>, String> {
    let elems = sequence_elements(&key_description_der(leaf_der)?)?;
    if elems.len() <= 4 {
        return Err("KeyDescription too short".into());
    }
    Ok(elems[4].value.clone())
}

pub fn fields(leaf_der: &[u8]) -> Result<AttestationFields, String> {
    let elems = sequence_elements(&key_description_der(leaf_der)?)?;
    let mut f = AttestationFields::default();
    if elems.len() > 1 && !elems[1].value.is_empty() {
        f.security_level = Some(elems[1].value[0] as i64);
    }

    // teeEnforced [7] preferred over softwareEnforced [6]; both are plain
    // SEQUENCEs whose entries carry the context tags.
    for idx in [7usize, 6] {
        if elems.len() <= idx || f.verified_boot_state.is_some() {
            continue;
        }
        for entry in tlv_list(&elems[idx].value)? {
            if entry.tag != ROOT_OF_TRUST_TAG {
                continue;
            }
            let rot = tlv_list(&entry.value)?;
            if rot.len() > 1 && !rot[1].value.is_empty() {
                f.device_locked = Some(rot[1].value[0] != 0);
            }
            if rot.len() > 2 && !rot[2].value.is_empty() {
                f.verified_boot_state = Some(rot[2].value[0] as i64);
            }
            break;
        }
        if f.verified_boot_state.is_some() {
            break;
        }
    }
    Ok(f)
}
