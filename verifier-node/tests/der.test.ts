// The minimal DER TLV reader (Der.kt port) — short/long/high-tag forms.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readTlv, tlvList, sequenceElements } from "../src/text/der.js";

test("reads short form tlv", () => {
  const [tlv, nxt] = readTlv(Buffer.from([0x02, 0x01, 0x05]), 0);
  assert.deepEqual(tlv.tag, Buffer.from([0x02]));
  assert.deepEqual(tlv.value, Buffer.from([0x05]));
  assert.equal(nxt, 3);
});

test("reads long form length", () => {
  const der = Buffer.concat([Buffer.from([0x04, 0x81, 0x80]), Buffer.alloc(128)]);
  const [tlv, nxt] = readTlv(der, 0);
  assert.deepEqual(tlv.tag, Buffer.from([0x04]));
  assert.equal(tlv.value.length, 128);
  assert.equal(nxt, 3 + 128);
});

test("reads two byte long form length", () => {
  const der = Buffer.concat([Buffer.from([0x04, 0x82, 0x01, 0x2c]), Buffer.alloc(300)]);
  const [tlv] = readTlv(der, 0);
  assert.equal(tlv.value.length, 300);
});

test("reads high tag number form", () => {
  const [tlv, nxt] = readTlv(Buffer.from([0x1f, 0x81, 0x00, 0x01, 0xaa]), 0);
  assert.deepEqual(tlv.tag, Buffer.from([0x1f, 0x81, 0x00]));
  assert.deepEqual(tlv.value, Buffer.from([0xaa]));
  assert.equal(nxt, 5);
});

test("sequence elements splits in order", () => {
  const els = sequenceElements(Buffer.from([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07]));
  assert.deepEqual(els.map(e => e.value), [Buffer.from([0x05]), Buffer.from([0x07])]);
});

test("tlv list walks a set value", () => {
  const els = tlvList(Buffer.from([0x04, 0x02, 0xde, 0xad, 0x04, 0x01, 0xbe]));
  assert.deepEqual(els[0].value, Buffer.from([0xde, 0xad]));
  assert.deepEqual(els[1].value, Buffer.from([0xbe]));
});
