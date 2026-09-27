"""The licence package contract: byte-identical to the reference generator
(tools/keys/gen-dev-licence.py) and to what dicore's licence_blob.cpp parses."""
import hashlib
import hmac
import importlib.util
import os
import pathlib
import stat
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from deviceintelligence_licence import PUBLISHER_KEY, build_blob, generate_licence

REPO = pathlib.Path(__file__).resolve().parents[2]
NATIVE = REPO / "deviceintelligence/src/main/cpp/dicore/crypto/licence_blob.cpp"


def _load_reference():
    spec = importlib.util.spec_from_file_location(
        "gen_dev_licence", REPO / "tools/keys/gen-dev-licence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fixed_key() -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes(range(32)))


def test_blob_layout_is_rvn2_144_bytes():
    blob = build_blob("com.example.app", epoch=7, not_after=1234567890,
                      private_key=_fixed_key())
    assert len(blob) == 144
    assert blob[0:4] == b"RVN2"
    assert blob[4] == 0x02                 # version
    assert blob[5] == 7                    # epoch, echoed
    assert blob[6] == 0x01                 # curve: X25519
    assert blob[7] == 0x00                 # flags


def test_pkg_hash_and_not_after_are_in_the_signed_region():
    blob = build_blob("com.example.app", epoch=0, not_after=1700000000,
                      private_key=_fixed_key())
    assert blob[8:40] == _fixed_key().public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw)
    assert blob[40:72] == hashlib.sha256(b"com.example.app").digest()
    assert blob[72:80] == (1700000000).to_bytes(8, "big")


def test_signature_is_hmac_over_body_and_reserved_is_zero():
    blob = build_blob("com.example.app", epoch=3, not_after=0, private_key=_fixed_key())
    assert blob[80:112] == hmac.new(PUBLISHER_KEY, blob[:80], hashlib.sha256).digest()
    assert blob[112:144] == bytes(32)


def test_epoch_is_a_uint8():
    with pytest.raises(ValueError):
        build_blob("com.example.app", epoch=256, not_after=0, private_key=_fixed_key())


def test_byte_identical_to_reference_script():
    reference_blob, _ = _load_reference().build("com.example.app", 7, 1700000000, _fixed_key())
    assert build_blob("com.example.app", epoch=7, not_after=1700000000,
                      private_key=_fixed_key()) == reference_blob


def test_generate_writes_the_two_files(tmp_path):
    material = generate_licence("com.example.app", epoch=5, out_dir=tmp_path)
    server_key = tmp_path / "server.key"
    pem = tmp_path / "server-priv-5.pem"
    assert server_key.read_bytes() == material.server_key
    assert len(material.server_key) == 144
    assert b"BEGIN PRIVATE KEY" in pem.read_bytes()
    assert pem.stat().st_mode & 0o777 == 0o600
    assert material.public_raw_hex == material.server_key[8:40].hex()


def test_embedded_publisher_key_matches_the_native_source():
    """Drift gate: if dicore's kPublisherKey ever changes, this fails."""
    assert NATIVE.exists(), "run from the repo checkout"
    text = NATIVE.read_text()
    hexes = text.split("kPublisherKey")[1].split("{")[1].split("}")[0]
    native = bytes(int(b, 16) for b in __import__("re").findall(r"0x([0-9a-fA-F]{2})", hexes))
    assert PUBLISHER_KEY == native
