// RFC 5869 known-answer tests — via the hkdf module.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "../src/hkdf.js";

const IKM22 = Buffer.from("0b".repeat(22), "hex");

test("rfc5869 case1 with salt and info", () => {
  const okm = sha256(IKM22, Buffer.from("000102030405060708090a0b0c", "hex"),
                     Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"), 42);
  assert.equal(okm.toString("hex"),
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
});

test("rfc5869 case3 empty salt and info", () => {
  const okm = sha256(IKM22, Buffer.alloc(0), Buffer.alloc(0), 42);
  assert.equal(okm.toString("hex"),
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
});

test("rejects output over 255 blocks", () => {
  assert.throws(() => sha256(Buffer.from([0x01]), Buffer.alloc(0), Buffer.alloc(0), 255 * 32 + 1));
});

test("token derivation shape is 32 bytes", () => {
  const key = sha256(Buffer.from("00".repeat(32), "hex"), Buffer.from("10".repeat(12), "hex"),
                     Buffer.from("intel-token-v2\x00", "utf8"), 32);
  assert.equal(key.length, 32);
});
