"""Hand-built Android KeyDescription DER (OID 1.3.6.1.4.1.11129.2.1.17) —
`cryptography` has no native builder for it. Field order and the EXPLICIT
RootOfTrust SEQUENCE mirror the real captures the verifiers parse."""
from .der_writer import boolean, enumerated, integer, octet_string, sequence, tlv

ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
ROOT_OF_TRUST_TAG = bytes([0xBF, 0x85, 0x40])       # [704], constructed
SECURITY_LEVELS = {0: "Software", 1: "TEE", 2: "StrongBox"}
BOOT_STATES = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}


def key_description_der(
    *,
    challenge: bytes,
    attestation_version: int = 3,
    security_level: int = 1,
    keymaster_version: int = 3,
    keymaster_security_level: int = 1,
    unique_id: bytes = b"",
    verified_boot_key: bytes = b"di-lab-root-of-trust",
    device_locked: bool = True,
    verified_boot_state: int = 0,
) -> bytes:
    # RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING,
    #   deviceLocked BOOLEAN, verifiedBootState ENUMERATED, hash OCTET STRING }
    # (AOSP field order — verifiedBootKey first, NOT the intuitive one).
    root_of_trust = tlv(ROOT_OF_TRUST_TAG, sequence(
        octet_string(verified_boot_key),
        boolean(device_locked),
        enumerated(verified_boot_state),
        octet_string(b"di-lab-verified-boot-hash"),
    ))
    tee_enforced = sequence(root_of_trust)
    software_enforced = sequence()
    return sequence(
        integer(attestation_version),
        enumerated(security_level),
        integer(keymaster_version),
        enumerated(keymaster_security_level),
        octet_string(challenge),
        octet_string(unique_id),
        software_enforced,
        tee_enforced,
    )
