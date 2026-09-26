"""The scan verification flow (ScanVerifier.kt port): bootstrap, steady-state,
adjudication, and the boot-state spoofer truth table."""
import json as _json
import time as _time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_public_key)
from .models import (Assurance, AttestedApp, AttestationLevel, Check, CheckKind,
                     Decision, DeviceFingerprint, ResolvedSignal, ScanResult,
                     ScanSession, AttestedPlatform)
from .registry import SignalRegistry
from .policy import Policy
from .attestation import (fields as _att_fields, challenge as _att_challenge,
                          attested_app as _att_app, attested_platform as _att_platform,
                          device_properties as _att_props)
from .token_crypto import decrypt as _v2_decrypt, is_v2
from .chain_verifier import parse_chain as _parse_chain, verify_to_pinned_root as _verify_root
from .crl import AttestationCrl
from .pinned_roots import default as _pinned_default
from .signals import resolve as _signals_resolve

FS = "\x1F"
BINDING_SEP = "\n--BINDING\n"


def boot_state_spoofer(reported: dict, fields) -> bool:
    """The consistent Play-Integrity-Fix buster: self-reported boot vs hardware."""
    vbs = (reported.get("vbs") or "").lower()
    flash_locked = reported.get("blocked") or ""
    vbmeta = (reported.get("vbmeta") or "").lower()
    self_claims_clean = vbs == "green" or flash_locked == "1" or vbmeta == "locked"
    attest_clean = fields is not None and fields.verified_boot_state == 0 \
        and fields.device_locked is True
    return self_claims_clean and not attest_clean


def _hex(s: str) -> bool:
    return bool(s) and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)


def _run(fn):
    try:
        return {"ok": True, "value": fn()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _binding_sig(binding: str) -> str:
    for line in binding.split("\n"):
        if line.startswith("SIG" + FS):
            return line[len("SIG" + FS):]
    return ""


def _fingerprint_of(doc: dict) -> DeviceFingerprint | None:
    fp = doc.get("fp")
    if not isinstance(fp, dict):
        return None
    def s(k):
        v = fp.get(k)
        return v if isinstance(v, str) and v else None
    return DeviceFingerprint(s("id"), s("aid"), s("lvl"), s("build"), s("kernel"),
                             s("patch"), s("installer"))


def _attestation_of(doc: dict):
    a = doc.get("attestation")
    if not isinstance(a, dict):
        return None
    return AttestationLevel.parse(a.get("level")), AttestationLevel.parse(a.get("signed")), \
        (a.get("reason") or "") or "UNKNOWN", a.get("detail") or None


class ScanVerifier:
    def __init__(self, pinned_roots=None, crl: AttestationCrl | None = None,
                 registry: SignalRegistry | None = None, policy: Policy | None = None,
                 licenses=None, now=None):
        self.pinned_roots = pinned_roots or _pinned_default()
        self.crl = crl or AttestationCrl.default()
        self.registry = registry or SignalRegistry.bundled()
        self.policy = policy or Policy()
        self.licenses = licenses if licenses is not None else LicenseRegistry()
        self._now = now or (lambda: int(_time.time()))

    def verify_scan(self, token: str, issued_session_id: str, server_priv,
                    session: ScanSession | None = None) -> ScanResult:
        checks: list = []
        def ck(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.AUTH)); return ok

        def fail(reason, bootstrap=False, signals=None, attestation=None, session=None):
            return ScanResult(False, bootstrap, False, session, checks, signals or [], reason,
                              attestation=attestation)

        if not ck("v2 envelope", is_v2(token)):
            return fail("not a v2 token")
        opened = _run(lambda: _v2_decrypt(token, server_priv))
        text = opened.get("value")
        if not ck("envelope opens", text is not None):
            return fail("envelope did not open")

        sep = text.find(BINDING_SEP)
        if not ck("binding present", sep >= 0):
            return fail("unbound")
        signed, binding = text[:sep], text[sep + len(BINDING_SEP):]

        parsed = _run(lambda: _json.loads(signed))
        doc = parsed.get("value") or {}
        if not ck("signed content is JSON", bool(doc)):
            return fail("bad json")

        bootstrap = doc.get("bootstrap") is True
        level, signed_lvl, reason, detail = _attestation_of(doc)
        signals = _signals_resolve(doc, self.registry, self.policy)
        degraded = (signed_lvl != AttestationLevel.ATTESTED) or not _binding_sig(binding)

        session_id_ok = ck("session id matches issued", doc.get("sessionId") == issued_session_id)

        if degraded:
            ck("token carries a hardware-attested binding", False,
               f"{reason} (signed={signed_lvl})")
            already = {s.id for s in signals}
            extra = [s for s in _degraded_signals(reason, signed_lvl, detail,
                                                  self.registry, self.policy)
                     if s.id not in already]
            return fail(f"unattested: {reason}", bootstrap, signals + extra,
                        session=None)

        if not session_id_ok:
            return fail("session id mismatch", bootstrap, signals)

        if bootstrap:
            return self._verify_bootstrap(doc, binding, issued_session_id, checks, signals)
        return self._verify_steady_state(doc, binding, signed, session, checks, signals)

    # ---- bootstrap ---------------------------------------------------------

    def _verify_bootstrap(self, doc, binding, issued_session_id, checks, signals):
        def ck(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.AUTH)); return ok

        def fail(reason, session=None):
            return ScanResult(False, True, False, session, checks, signals, reason)

        certs, sb, tee = [], [], []
        for line in binding.split("\n"):
            if line.startswith("CERT"): certs.append(line[5:])
            elif line.startswith("XLEVEL_SB"): sb.append(line[10:])
            elif line.startswith("XLEVEL_TEE"): tee.append(line[11:])

        if not ck("chain present", bool(certs)):
            return fail("no chain")
        chain = _run(lambda: _parse_chain(certs)).get("value")
        if not chain:
            ck("chain parses", False)
            return fail("chain parse")
        leaf = chain[0]

        root = _run(lambda: _verify_root(chain, self.pinned_roots))
        if not ck("chain -> pinned Google root", root.get("ok"),
                  _subject(root.get("value")) if root.get("ok") else root.get("error", "chain error")):
            return fail("chain does not reach a pinned Google root")

        challenge = _run(lambda: _att_challenge(leaf)).get("value")
        if not ck("attestation challenge == session id",
                  challenge is not None and challenge == issued_session_id.encode("utf-8")):
            return fail("attestation not bound to this session")

        spki = doc.get("attestedKey")
        if not ck("attested key present and hex", isinstance(spki, str) and _hex(spki)):
            return fail("attestedKey missing or not hex")

        fields = _run(lambda: _att_fields(leaf)).get("value")
        platform = _run(lambda: _att_platform(leaf)).get("value") or \
            AttestedPlatform(None, None, None, None)
        assurance = (Assurance.STRONGBOX if fields is not None and fields.security_level == 2
                     else Assurance.TEE if fields is not None and fields.security_level == 1
                     else Assurance.SOFTWARE)
        software_attested = fields is not None and fields.security_level == 0

        xlevel = _run(lambda: _cross_level(sb, tee, assurance, self.pinned_roots)).get("value") \
            or (False, False)
        reuse, sb_missing = xlevel
        revoked_serial = _run(lambda: self.crl.first_revoked(
            chain,
            _parse_chain(sb) if len(sb) >= 2 else [],
            _parse_chain(tee) if len(tee) >= 2 else [])).get("value")

        reported = doc.get("device") or {}
        attested_props = _run(lambda: _att_props(leaf)).get("value") or {}
        prop_mismatch = _prop_mismatch(attested_props, reported)
        spoofer = boot_state_spoofer(reported, fields)

        sb_feature = {"1": True, "0": False}.get(reported.get("sbFeature"))
        strongbox_transient = assurance != Assurance.STRONGBOX and len(sb) < 2 \
            and sb_feature is True

        session = ScanSession(
            attested_key=spki,
            attested_app=_run(lambda: _att_app(leaf)).get("value"),
            assurance=assurance,
            boot_state=fields.boot_state_name if fields else "?",
            device_locked=fields.device_locked is True if fields is not None else False,
            chain_trusted=True,
            keybox_revoked=revoked_serial is not None,
            cross_level_reuse=reuse,
            device_prop_mismatch=prop_mismatch is not None,
            boot_state_spoofer=spoofer,
            strongbox_chain_missing=sb_missing or strongbox_transient,
            software_attested=software_attested,
            os_patch_level=platform.os_patch_level,
            vendor_patch_level=platform.vendor_patch_level,
            boot_patch_level=platform.boot_patch_level,
            fingerprint=_fingerprint_of(doc))
        return self._adjudicate(doc, session, checks, signals, revoked_serial,
                                prop_mismatch, bootstrap=True)

    # ---- steady state ------------------------------------------------------

    def _verify_steady_state(self, doc, binding, signed, session, checks, signals):
        def ck(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.AUTH)); return ok

        registry, policy = self.registry, self.policy
        all_signals = signals \
            + _app_signals(doc, session.attested_app if session else None, self.licenses,
                           registry, policy) \
            + (_carried_signals(session, registry, policy) if session else [])

        def fail(reason):
            return ScanResult(False, False, False, None, checks, all_signals, reason)

        if session is None:
            ck("session carried from bootstrap", False)
            return fail("no bound key for session")
        ck("session carried from bootstrap", True)

        sig_hex = _binding_sig(binding)
        if not ck("signature present", bool(sig_hex)):
            return fail("no signature")

        verified = _run(lambda: self._verify_ecdsa(signed, sig_hex, session.attested_key)) \
            .get("ok", False)
        if not ck("signature by the bound key", verified,
                  "" if verified else "ECDSA verify failed"):
            return fail("signature does not verify")

        return self._adjudicate(doc, session, checks, signals, None, None,
                                bootstrap=False)

    # ---- adjudication ------------------------------------------------------

    def _adjudicate(self, doc, session, checks, signals, revoked_serial, prop_mismatch,
                    bootstrap):
        def auth(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.AUTH))
        def integ(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.INTEGRITY))

        auth("attestation chain trusted", session.chain_trusted,
             "" if session.chain_trusted else "chain does not reach a pinned Google root")
        auth("no revoked keybox", not session.keybox_revoked,
             f"revoked serial {revoked_serial}" if revoked_serial else "")
        auth("no cross-level keybox reuse", not session.cross_level_reuse,
             "same batch key across StrongBox and TEE — leaked keybox"
             if session.cross_level_reuse else "")
        auth("device-property attestation matches self-report", not session.device_prop_mismatch,
             prop_mismatch or "")
        auth("boot-state self-report matches hardware attestation", not session.boot_state_spoofer,
             "self-report claims clean/locked boot but attestation says otherwise — prop spoofer"
             if session.boot_state_spoofer else "")

        integ("hardware security level >= TEE", session.assurance != Assurance.SOFTWARE,
              session.assurance.name)
        if self.policy.require_strong_box:
            integ("StrongBox required by policy", session.assurance == Assurance.STRONGBOX,
                  session.assurance.name)
        integ("verified boot state = Verified", session.boot_state == "Verified",
              session.boot_state)
        integ("device locked", session.device_locked, str(session.device_locked))

        registry, policy = self.registry, self.policy
        all_signals = signals \
            + _app_signals(doc, session.attested_app, self.licenses, registry, policy) \
            + _carried_signals(session, registry, policy) \
            + _patch_signals(doc, session, policy, self._now)

        ok = all(c.ok for c in checks if c.kind == CheckKind.AUTH)
        integrity_ok = all(c.ok for c in checks if c.kind == CheckKind.INTEGRITY)
        reason = next((c.name for c in checks if c.kind == CheckKind.AUTH and not c.ok), None)

        return ScanResult(ok, bootstrap, integrity_ok,
                          session if bootstrap else None, checks, all_signals, reason,
                          session.fingerprint or _fingerprint_of(doc))

    @staticmethod
    def _verify_ecdsa(signed: str, sig_hex: str, spki_hex: str) -> bool:
        pub = load_der_public_key(bytes.fromhex(spki_hex))
        pub.verify(bytes.fromhex(sig_hex), signed.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True


# ---- flow helpers (stateless; registry/policy passed explicitly) -----------

def _degraded_signals(reason, signed_level, detail, registry, policy) -> list:
    out: list = []
    detail_txt = f" ({detail})" if detail else ""
    def add(sid, text):
        from .models import ResolvedSignal
        m = registry[sid]
        if m:
            out.append(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, text,
                                      policy.is_blocking(m.id, m.severity)))
    if reason == "NO_SESSION":
        add("INTEL_0023", f"scan issued with no prepared session{detail_txt}")
    elif reason in ("LICENCE_EXPIRED", "LICENCE_PKG_MISMATCH", "LICENCE_UNPARSEABLE"):
        add("INTEL_0038", f"licence rejected at scan time: {reason}{detail_txt}")
    else:
        add("INTEL_0030", f"attestation unavailable: {reason}{detail_txt}")
    if signed_level == AttestationLevel.NONE:
        add("INTEL_0015", "token carries no signature")
    return out


def _app_signals(doc, attested, licenses, registry, policy) -> list:
    if attested is None:
        return []
    app = doc.get("app")
    if not isinstance(app, dict):
        return []
    pkg = app.get("package") or ""
    signer = app.get("signer") or ""
    if not pkg or not signer:
        return []

    def sig(sid, detail):
        from .models import ResolvedSignal
        m = registry[sid]
        return [ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                               policy.is_blocking(m.id, m.severity))] if m else []

    agrees = pkg in attested.package_names and \
        any(d.lower() == signer.lower() for d in attested.signature_digests)
    if not agrees:
        first = attested.package_names[0] if attested.package_names else "?"
        return sig("INTEL_0046", f"reported={pkg}/{signer[:16]}… attested={first}")
    if not licenses.is_licensed(pkg, signer):
        return sig("INTEL_0037", f"package={pkg}")
    return []


def _carried_signals(session, registry, policy) -> list:
    from .models import ResolvedSignal
    out: list = []
    def add(sid, detail):
        from .models import ResolvedSignal
        m = registry[sid]
        if m:
            out.append(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                                      policy.is_blocking(m.id, m.severity)))
    if session.boot_state_spoofer:
        add("INTEL_0055", "self-report=green/locked but hardware attestation disagrees")
    if session.cross_level_reuse:
        add("INTEL_0016", "same attestation batch key across StrongBox and TEE — leaked keybox")
    if session.strongbox_chain_missing:
        add("INTEL_0045", "StrongBox hardware indicated but no StrongBox attestation chain produced")
    if session.software_attested:
        add("INTEL_0056", "attestation reports securityLevel=Software — no hardware root of trust")
    return out


def _patch_signals(doc, session, policy, now) -> list:
    from .models import ResolvedSignal
    out: list = []
    def add(sid, detail):
        m = registry[sid]
        if m:
            out.append(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                                      policy.is_blocking(m.id, m.severity)))

    def patch_to_epoch(v: int):
        try:
            y, m, d = (v // 10000, v // 100 % 100, v % 100) if v > 999999 \
                else (v // 100, v % 100, 1)
            if not 1 <= m <= 12 or not 1 <= d <= 31:
                return None
            import datetime
            return int(datetime.date(y, m, d).toordinal()) * 86_400
        except Exception:
            return None

    epochs = [e for e in (patch_to_epoch(p) for p in
             [session.os_patch_level, session.vendor_patch_level, session.boot_patch_level]
             if p is not None) if e is not None]
    if epochs:
        age_days = (now() - min(epochs)) // 86_400
        if age_days > policy.max_patch_age_days:
            add("INTEL_0050", f"oldest attested patch is {age_days} days old "
                f"(policy window {policy.max_patch_age_days})")

    attested_month = session.os_patch_level
    fp = _fingerprint_of(doc) if doc is not None else None
    reported = (session.fingerprint or fp).patch if (session.fingerprint or fp) else None
    if attested_month is not None and reported:
        try:
            reported_month = int(reported[0:4]) * 100 + int(reported[5:7])
        except Exception:
            reported_month = None
        if reported_month is not None and reported_month != attested_month:
            add("INTEL_0019", f"self-report {reported} vs attested {attested_month}")
    return out


def _cross_level(sb_hex, tee_hex, assurance, pinned_roots):
    if assurance == Assurance.STRONGBOX and len(sb_hex) < 2:
        return (True, True)
    if len(sb_hex) < 2 or len(tee_hex) < 2:
        return (False, False)
    sb_batch = _parse_chain(sb_hex)[1].public_key()
    tee_batch = _parse_chain(tee_hex)[1].public_key()
    from cryptography.hazmat.primitives import serialization
    a = sb_batch.public_bytes(serialization.Encoding.DER,
                              serialization.PublicFormat.SubjectPublicKeyInfo)
    b = tee_batch.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
    return (a == b, False)


def _prop_mismatch(attested: dict, reported: dict) -> str | None:
    for k, a in attested.items():
        r = reported.get(k)
        if not isinstance(r, str):
            continue
        if a and r and a.lower() != r.lower():
            return f"attested {k}='{a}' != reported '{r}'"
    return None


def LicenseRegistry():
    class _LicenseRegistry:
        def is_licensed(self, package: str, signer: str) -> bool:
            return True
    return _LicenseRegistry()
