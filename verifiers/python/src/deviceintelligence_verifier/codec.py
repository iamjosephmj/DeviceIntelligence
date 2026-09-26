"""JSON round-trip for ScanSession (ScanSessionCodec.kt port).

Decode contract: a truncated document grades DOWN to the suspicious value, never
to the benign default — an attacker-reachable decoder must not read as clean.
"""
import json
from .models import Assurance, AttestedApp, DeviceFingerprint, ScanSession

_SUSPICIOUS = dict(chain_trusted=False, keybox_revoked=True, cross_level_reuse=True,
                   device_prop_mismatch=True, boot_state_spoofer=True,
                   strongbox_chain_missing=True, software_attested=True)


def decode(json_text: str) -> ScanSession:
    try:
        o = json.loads(json_text)
    except ValueError as e:
        raise ValueError(f"not a JSON object: {e}")
    if not isinstance(o, dict):
        raise ValueError("not a JSON object")
    key = o.get("attestedKey")
    if not isinstance(key, str):
        raise ValueError("session has no attestedKey")
    app = o.get("attestedApp")
    attested_app = AttestedApp(
        [x for x in (app.get("packageNames") or []) if isinstance(x, str)],
        [x for x in (app.get("signatureDigests") or []) if isinstance(x, str)]) \
        if isinstance(app, dict) else None
    fp = o.get("fingerprint")
    fingerprint = DeviceFingerprint(fp.get("id"), fp.get("aid"), fp.get("securityLevel"),
                                    fp.get("build"), fp.get("kernel"), fp.get("patch"),
                                    fp.get("installer")) if isinstance(fp, dict) else None
    try:
        assurance = Assurance[o.get("assurance")]
    except KeyError:
        assurance = Assurance.SOFTWARE
    # An unknown or absent assurance grades DOWN, never up. These default to the
    # SUSPICIOUS value when absent — a truncated document must not read as clean.
    return ScanSession(
        attested_key=key, attested_app=attested_app, assurance=assurance,
        boot_state=o.get("bootState", "?"), device_locked=o.get("deviceLocked") is True,
        chain_trusted=o.get("chainTrusted") is True,
        keybox_revoked=o.get("keyboxRevoked") is not False,
        cross_level_reuse=o.get("crossLevelReuse") is not False,
        device_prop_mismatch=o.get("devicePropMismatch") is not False,
        boot_state_spoofer=o.get("bootStateSpoofer") is not False,
        strongbox_chain_missing=o.get("strongboxChainMissing") is not False,
        software_attested=o.get("softwareAttested") is not False,
        os_patch_level=o.get("osPatchLevel"), vendor_patch_level=o.get("vendorPatchLevel"),
        boot_patch_level=o.get("bootPatchLevel"), fingerprint=fingerprint,
        **{k: v for k, v in _SUSPICIOUS.items() if False})


def encode(s: ScanSession) -> str:
    def q(v):
        return json.dumps(v)
    fields = ['"attestedKey":' + q(s.attested_key)]
    if s.attested_app is None:
        fields.append('"attestedApp":null')
    else:
        app = s.attested_app
        pkgs = ",".join(q(x) for x in app.package_names)
        digs = ",".join(q(x) for x in app.signature_digests)
        fields.append('"attestedApp":{"packageNames":[' + pkgs + '],"signatureDigests":[' + digs + ']}')
    fields.append('"assurance":' + q(s.assurance.name))
    fields.append('"bootState":' + q(s.boot_state))
    fields.append('"deviceLocked":' + ("true" if s.device_locked else "false"))
    fields.append('"chainTrusted":' + ("true" if s.chain_trusted else "false"))
    fields.append('"keyboxRevoked":' + ("true" if s.keybox_revoked else "false"))
    fields.append('"crossLevelReuse":' + ("true" if s.cross_level_reuse else "false"))
    fields.append('"devicePropMismatch":' + ("true" if s.device_prop_mismatch else "false"))
    fields.append('"bootStateSpoofer":' + ("true" if s.boot_state_spoofer else "false"))
    fields.append('"strongboxChainMissing":' + ("true" if s.strongbox_chain_missing else "false"))
    fields.append('"softwareAttested":' + ("true" if s.software_attested else "false"))
    for k, v in (("osPatchLevel", s.os_patch_level), ("vendorPatchLevel", s.vendor_patch_level),
                 ("bootPatchLevel", s.boot_patch_level)):
        fields.append(f'"{k}":' + ("null" if v is None else str(v)))
    if s.fingerprint is None:
        fields.append('"fingerprint":null')
    else:
        fp = s.fingerprint
        pairs = ",".join(q(k) + ":" + ("null" if v is None else q(v)) for k, v in
                         (("id", fp.id), ("aid", fp.aid), ("securityLevel", fp.security_level),
                          ("build", fp.build), ("kernel", fp.kernel), ("patch", fp.patch),
                          ("installer", fp.installer)))
        fields.append('"fingerprint":{' + pairs + '}')
    return "{" + ",".join(fields) + "}"
