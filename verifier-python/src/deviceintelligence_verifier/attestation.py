"""Android Key Attestation extension reader (Attestation.kt port). Minimal DER walk."""
from .der import read_tlv, tlv_list, sequence_elements
from .models import AttestationFields, AttestedApp, AttestedPlatform

OID = "1.3.6.1.4.1.11129.2.1.17"
ROOT_OF_TRUST_TAG = bytes([0xBF, 0x85, 0x40])
ATTEST_APP_ID_TAG = bytes([0xBF, 0x85, 0x45])
OS_VERSION_TAG = bytes([0xBF, 0x85, 0x41])
OS_PATCH_LEVEL_TAG = bytes([0xBF, 0x85, 0x42])
VENDOR_PATCH_TAG = bytes([0xBF, 0x85, 0x4E])
BOOT_PATCH_TAG = bytes([0xBF, 0x85, 0x4F])
ATTEST_ID = [("brand", bytes([0xBF, 0x85, 0x46])), ("device", bytes([0xBF, 0x85, 0x47])),
             ("product", bytes([0xBF, 0x85, 0x48])), ("manufacturer", bytes([0xBF, 0x85, 0x4C])),
             ("model", bytes([0xBF, 0x85, 0x4D]))]


def _key_description_der(cert):
    raw = cert.get_extension_for_class(type(__import__("cryptography").x509.extensions.ExtensionNotFound)
                                       and __import__("cryptography").x509).value if False else None
    # getExtensionValue equivalent: the extnValue OCTET STRING wrapping the KeyDescription.
    ext = None
    for e in cert.extensions:
        if e.oid.dotted_string == OID:
            ext = e.value.value  # the unwrapped OCTET STRING payload
            break
    if ext is None:
        raise ValueError("no Android attestation extension on leaf")
    return ext


def challenge(cert) -> bytes:
    elems = sequence_elements(_key_description_der(cert))
    return elems[4].value


def fields(cert) -> AttestationFields:
    elems = sequence_elements(_key_description_der(cert))
    sec_level = None
    if len(elems) > 1 and elems[1].value:
        sec_level = elems[1].value[0] & 0xFF
    boot_state = locked = None
    for auth_idx in (7, 6):                      # teeEnforced, then softwareEnforced
        if len(elems) <= auth_idx:
            continue
        for tlv in tlv_list(elems[auth_idx].value):
            if tlv.tag == ROOT_OF_TRUST_TAG:
                inner, _ = read_tlv(tlv.value, 0)
                rot = tlv_list(inner.value)
                if len(rot) > 1 and rot[1].value:
                    locked = rot[1].value[0] != 0
                if len(rot) > 2 and rot[2].value:
                    boot_state = rot[2].value[0] & 0xFF
                break
        if boot_state is not None:
            break
    return AttestationFields(sec_level, boot_state, locked)


def device_properties(cert) -> dict:
    elems = sequence_elements(_key_description_der(cert))
    out = {}
    for auth_idx in (7, 6):
        if len(elems) <= auth_idx:
            continue
        for tlv in tlv_list(elems[auth_idx].value):
            for name, tag in ATTEST_ID:
                if tlv.tag == tag and name not in out:
                    octet, _ = read_tlv(tlv.value, 0)
                    out[name] = octet.value.decode("ascii")
    return out


def attested_app(cert):
    elems = sequence_elements(_key_description_der(cert))
    for auth_idx in (6, 7):                      # softwareEnforced carries tag 709
        if len(elems) <= auth_idx:
            continue
        for tlv in tlv_list(elems[auth_idx].value):
            if tlv.tag != ATTEST_APP_ID_TAG:
                continue
            octet, _ = read_tlv(tlv.value, 0)
            inner = sequence_elements(octet.value)
            pkgs = [bytes(info.value).decode("utf-8") if False else
                    tlv_list(info.value)[0].value.decode("utf-8")
                    for info in tlv_list(inner[0].value)]
            digests = [tlv.value.hex() for tlv in tlv_list(inner[1].value)]
            if not pkgs and not digests:
                return None
            return AttestedApp(pkgs, digests)
    return None


def attested_platform(cert) -> AttestedPlatform:
    try:
        elems = sequence_elements(_key_description_der(cert))
    except Exception:
        return AttestedPlatform(None, None, None, None)
    os_v = os_p = v_p = b_p = None
    for auth_idx in (7, 6):
        if len(elems) <= auth_idx:
            continue
        for tlv in tlv_list(elems[auth_idx].value):
            try:
                inner, _ = read_tlv(tlv.value, 0)
                acc = 0
                for b in inner.value:
                    acc = (acc << 8) | (b & 0xFF)
                v = acc
            except Exception:
                continue
            if tlv.tag == OS_VERSION_TAG and os_v is None: os_v = v
            elif tlv.tag == OS_PATCH_LEVEL_TAG and os_p is None: os_p = v
            elif tlv.tag == VENDOR_PATCH_TAG and v_p is None: v_p = v
            elif tlv.tag == BOOT_PATCH_TAG and b_p is None: b_p = v
    return AttestedPlatform(os_v, os_p, v_p, b_p)
