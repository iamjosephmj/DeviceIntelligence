// The v2 ECIES contract: the native-interop KAT, the tamper matrix, malformed input.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decryptV2, isV2 } from "../src/tokens/token_crypto.js";

const SERVER_PRIV_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TOKEN = ("2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213"
              + "1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a"
              + "2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b");
const EMPTY_TOKEN = ("2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011"
                    + "12131415161718191a1b9a7f7296f43354e241400ee7b8946c46");
const EXPECTED = "signed_content\n--BINDING\nSIG...\nCERT...";

const flipAt = (token: string, i: number): string => {
  const body = token.slice(2).split("");
  body[i] = body[i] === "0" ? "1" : "0";
  return "2:" + body.join("");
};

test("decrypts native v2 token", () => {
  const out = decryptV2(TOKEN, Buffer.from(SERVER_PRIV_HEX, "hex"));
  assert.equal(out.toString("utf8"), EXPECTED);
});

test("decrypts empty ciphertext token", () => {
  const out = decryptV2(EMPTY_TOKEN, Buffer.from(SERVER_PRIV_HEX, "hex"));
  assert.equal(out.length, 0);
});

for (const i of [0, 2, 10, 70, 92]) {
  test(`tamper at body index ${i} fails the gcm tag`, () => {
    assert.throws(() => decryptV2(flipAt(TOKEN, i), Buffer.from(SERVER_PRIV_HEX, "hex")));
  });
}

test("tamper tag fails", () => {
  assert.throws(() => decryptV2(flipAt(TOKEN, TOKEN.length - 3),
                                Buffer.from(SERVER_PRIV_HEX, "hex")));
});

test("wrong server key fails", () => {
  const other = "0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21";
  assert.throws(() => decryptV2(TOKEN, Buffer.from(other, "hex")));
});

test("all zero ephemeral point throws", () => {
  const body = TOKEN.slice(2).split("");
  for (let i = 4; i < 68; i++) body[i] = "0";
  assert.throws(() => decryptV2("2:" + body.join(""), Buffer.from(SERVER_PRIV_HEX, "hex")));
});

test("rejects missing prefix", () => {
  assert.throws(() => decryptV2("deadbeefcafe", Buffer.from(SERVER_PRIV_HEX, "hex")),
                /not a v2 token/);
});

test("rejects too short payload", () => {
  assert.throws(() => decryptV2("2:0203", Buffer.from(SERVER_PRIV_HEX, "hex")));
});

test("rejects odd length hex", () => {
  assert.throws(() => decryptV2("2:abc", Buffer.from(SERVER_PRIV_HEX, "hex")));
});

test("rejects non hex chars", () => {
  assert.throws(() => decryptV2("2:zzzz", Buffer.from(SERVER_PRIV_HEX, "hex")));
});

test("is v2 discriminates from v1", () => {
  assert.equal(isV2(TOKEN), true);
  assert.equal(isV2("deadbeefcafe"), false);
  assert.equal(isV2(""), false);
  assert.equal(isV2("2"), false);
});
