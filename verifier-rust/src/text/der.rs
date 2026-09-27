//! Minimal DER TLV reader (Der.kt port) — short/long/high-tag forms, exactly
//! what the KeyDescription walk needs.

#[derive(Clone, Debug)]
pub struct Tlv {
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
    /// The complete TLV (tag, length, value) exactly as encoded — the bytes
    /// a signature is computed over when this element is a tbsCertificate.
    pub raw: Vec<u8>,
}

pub fn read_tlv(b: &[u8], i0: usize) -> Result<(Tlv, usize), String> {
    let mut i = i0;
    if i >= b.len() {
        return Err("DER truncated".into());
    }
    let start = i;
    let t = b[i] as usize;
    i += 1;
    if t & 0x1f == 0x1f {
        // high-tag-number form
        while i < b.len() && b[i] & 0x80 != 0 {
            i += 1;
        }
        i += 1;
    }
    let tag = b[start..i].to_vec();
    if i >= b.len() {
        return Err("DER truncated".into());
    }
    let n = b[i] as usize;
    i += 1;
    let mut length = n;
    if n >= 0x80 {
        let k = n & 0x7f;
        if k == 0 || i + k > b.len() {
            return Err("bad DER length".into());
        }
        length = 0;
        for j in 0..k {
            length = (length << 8) | b[i + j] as usize;
        }
        i += k;
    }
    if i + length > b.len() {
        return Err("DER value out of range".into());
    }
    let value = b[i..i + length].to_vec();
    Ok((
        Tlv {
            tag,
            value,
            raw: b[start..i + length].to_vec(),
        },
        i + length,
    ))
}

pub fn tlv_list(seq: &[u8]) -> Result<Vec<Tlv>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < seq.len() {
        let (tlv, next) = read_tlv(seq, i)?;
        out.push(tlv);
        i = next;
    }
    Ok(out)
}

pub fn sequence_elements(der: &[u8]) -> Result<Vec<Tlv>, String> {
    let (outer, _) = read_tlv(der, 0)?;
    tlv_list(&outer.value)
}
