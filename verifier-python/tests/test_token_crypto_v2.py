"""The v2 ECIES contract: the native-interop KAT, the tamper matrix, malformed input."""
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from deviceintelligence_verifier import token_crypto

SERVER_PRIV_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
TOKEN = ("2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213"
         "1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a"
         "2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b")
EMPTY_TOKEN = ("2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011"
               "12131415161718191a1b9a7f7296f43354e241400ee7b8946c46")
EXPECTED = "signed_content\n--BINDING\nSIG...\nCERT..."


def priv(hex_str):
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def flip_at(token, i):
    body = list(token[2:])
    body[i] = "1" if body[i] == "0" else "0"
    return "2:" + "".join(body)


def test_decrypts_native_v2_token():
    out = token_crypto.decrypt(TOKEN, priv(SERVER_PRIV_HEX))
    assert out.decode("utf-8") == EXPECTED


def test_decrypts_empty_ciphertext_token():
    assert token_crypto.decrypt(EMPTY_TOKEN, priv(SERVER_PRIV_HEX)) == b""


@pytest.mark.parametrize("i", [0, 2, 10, 70, 92])
def test_tamper_fails(i):
    with pytest.raises(InvalidTag):
        token_crypto.decrypt(flip_at(TOKEN, i), priv(SERVER_PRIV_HEX))


def test_tamper_tag_fails():
    with pytest.raises(InvalidTag):
        token_crypto.decrypt(flip_at(TOKEN, len(TOKEN) - 3), priv(SERVER_PRIV_HEX))


def test_wrong_server_key_fails():
    other = "0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
    with pytest.raises(InvalidTag):
        token_crypto.decrypt(TOKEN, priv(other))


def test_all_zero_ephemeral_point_throws():
    body = list(TOKEN[2:])
    for i in range(4, 68):
        body[i] = "0"
    bad = "2:" + "".join(body)
    with pytest.raises(Exception):
        token_crypto.decrypt(bad, priv(SERVER_PRIV_HEX))


def test_rejects_missing_prefix():
    with pytest.raises(ValueError):
        token_crypto.decrypt("deadbeefcafe", priv(SERVER_PRIV_HEX))


def test_rejects_too_short_payload():
    with pytest.raises(ValueError):
        token_crypto.decrypt("2:0203", priv(SERVER_PRIV_HEX))


def test_rejects_odd_length_hex():
    with pytest.raises(ValueError):
        token_crypto.decrypt("2:abc", priv(SERVER_PRIV_HEX))


def test_rejects_non_hex_chars():
    with pytest.raises(ValueError):
        token_crypto.decrypt("2:zzzz", priv(SERVER_PRIV_HEX))


def test_is_v2_discriminates_from_v1():
    assert token_crypto.is_v2(TOKEN)
    assert not token_crypto.is_v2("deadbeefcafe")
    assert not token_crypto.is_v2("")
    assert not token_crypto.is_v2("2")
