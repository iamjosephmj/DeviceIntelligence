// Minimal DER TLV reader (Der.kt port) — high-tag numbers included.
export interface Tlv { tag: Buffer; value: Buffer; }

export function readTlv(b: Buffer, i0: number): [Tlv, number] {
  let i = i0;
  const start = i;
  const t = b[i] & 0xff; i += 1;
  if ((t & 0x1f) === 0x1f) {           // high-tag-number form
    while ((b[i] & 0x80) !== 0) i += 1;
    i += 1;
  }
  const tag = b.subarray(start, i);
  let n = b[i] & 0xff; i += 1;
  let length: number;
  if (n < 0x80) length = n;
  else {
    const k = n & 0x7f;
    let v = 0;
    for (let j = 0; j < k; j++) { v = (v << 8) | (b[i] & 0xff); i += 1; }
    length = v;
  }
  const value = Buffer.from(b.subarray(i, i + length));
  return [{ tag, value }, i + length];
}

export function tlvList(seqValue: Buffer): Tlv[] {
  const out: Tlv[] = [];
  let i = 0;
  while (i < seqValue.length) {
    const [tlv, next] = readTlv(seqValue, i);
    out.push(tlv); i = next;
  }
  return out;
}

export function sequenceElements(der: Buffer): Tlv[] {
  const [outer] = readTlv(der, 0);
  return tlvList(outer.value);
}
