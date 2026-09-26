"""The verify/decision vocabulary and the scan/session facts (Model.kt + ScanModel.kt)."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Decision(Enum):
    TRUSTWORTHY = "TRUSTWORTHY"
    COMPROMISED = "COMPROMISED"
    REJECT = "REJECT"


class CheckKind(Enum):
    AUTH = "AUTH"
    INTEGRITY = "INTEGRITY"


class Assurance(Enum):
    SOFTWARE = "SOFTWARE"
    TEE = "TEE"
    STRONGBOX = "STRONGBOX"


class AttestationLevel(Enum):
    ATTESTED = "ATTESTED"
    SOFTWARE = "SOFTWARE"
    NONE = "NONE"

    @staticmethod
    def parse(s: Optional[str]) -> "AttestationLevel":
        """Unknown values grade DOWN: this decodes attacker-reachable input."""
        for level in AttestationLevel:
            if level.name.lower() == (s or "").lower():
                return level
        return AttestationLevel.NONE


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    kind: CheckKind


@dataclass
class DeviceInfo:
    api: Optional[int]
    abi: Optional[str]
    model: Optional[str]


@dataclass
class ResolvedSignal:
    id: str
    detector: str
    kind: str
    title: str
    severity: str
    detail: str
    blocking: bool
    attributes: dict = field(default_factory=dict)

    @property
    def module_id(self) -> Optional[str]:
        return self.attributes.get("module_id")

    @property
    def path(self) -> Optional[str]:
        return self.attributes.get("path")

    @property
    def linked_libraries(self) -> list:
        raw = self.attributes.get("needed")
        return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

    @property
    def links_hook_lib(self) -> Optional[str]:
        return self.attributes.get("links_hook_lib")

    @property
    def hooked_symbol(self) -> Optional[str]:
        return self.attributes.get("hooked_symbol")

    @property
    def hooked_by(self) -> Optional[str]:
        return self.attributes.get("hooked_by")

    @property
    def hook_stub_regions(self) -> Optional[int]:
        v = self.attributes.get("hook_stub_regions")
        return int(v) if v is not None else None

    @property
    def is_confirmed_hook_pool(self) -> bool:
        return self.kind == "rwx_memory_mapping" and (self.hook_stub_regions or 0) > 0


def definitive_hooks(signals: list) -> list:
    """Symbols confirmed hooked by BOTH a structural and a behavioral signal."""
    structural = {s.hooked_symbol for s in signals
                  if s.kind in ("libc_inline_hook", "libc_inline_stub") and s.hooked_symbol}
    behavioral = {s.hooked_symbol for s in signals
                  if s.kind == "syscall_divergence" and s.hooked_symbol}
    return sorted(structural & behavioral)


def confirmed_hook_pools(signals: list) -> list:
    return [s for s in signals if s.is_confirmed_hook_pool]


@dataclass
class DecodedToken:
    schema_version: Optional[int]
    point: Optional[str]
    ts: Optional[int]
    nonce: Optional[str]
    device: Optional[DeviceInfo]
    signals: list
    has_binding: bool


@dataclass
class TokenAttestation:
    level: AttestationLevel
    signed: AttestationLevel
    reason: str
    detail: Optional[str] = None

    @property
    def degraded(self) -> bool:
        return self.signed != AttestationLevel.ATTESTED


@dataclass
class AttestedApp:
    package_names: list
    signature_digests: list


@dataclass
class DeviceFingerprint:
    id: Optional[str]
    aid: Optional[str]
    security_level: Optional[str]
    build: Optional[str]
    kernel: Optional[str]
    patch: Optional[str]
    installer: Optional[str]


@dataclass
class AttestationFields:
    security_level: Optional[int]
    verified_boot_state: Optional[int]
    device_locked: Optional[bool]

    SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
    BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}

    @property
    def security_level_name(self) -> str:
        return self.SECURITY_LEVEL.get(self.security_level) or (
            str(self.security_level) if self.security_level is not None else "?")

    @property
    def boot_state_name(self) -> str:
        return self.BOOT_STATE.get(self.verified_boot_state) or (
            str(self.verified_boot_state) if self.verified_boot_state is not None else "?")


@dataclass
class AttestedPlatform:
    os_version: Optional[int]
    os_patch_level: Optional[int]
    vendor_patch_level: Optional[int]
    boot_patch_level: Optional[int]


@dataclass
class ScanSession:
    attested_key: str
    attested_app: Optional[AttestedApp]
    assurance: Assurance
    boot_state: str
    device_locked: bool
    chain_trusted: bool = True
    keybox_revoked: bool = False
    cross_level_reuse: bool = False
    device_prop_mismatch: bool = False
    boot_state_spoofer: bool = False
    strongbox_chain_missing: bool = False
    software_attested: bool = False
    os_patch_level: Optional[int] = None
    vendor_patch_level: Optional[int] = None
    boot_patch_level: Optional[int] = None
    fingerprint: Optional[DeviceFingerprint] = None


@dataclass
class Session:
    pinned_key_spki_hex: str
    assurance: Assurance
    boot_state: str
    device_locked: bool
    issued_at: int
    chain_trusted: bool = True
    keybox_revoked: bool = False
    cross_level_reuse: bool = False
    strongbox_chain_missing: bool = False
    device_prop_mismatch: bool = False
    boot_state_spoofer: bool = False
    software_attested: bool = False


@dataclass
class ScanResult:
    ok: bool
    bootstrap: bool
    device_integrity_ok: bool
    session: Optional[ScanSession]
    checks: list
    signals: list
    reason: Optional[str]
    fingerprint: Optional[DeviceFingerprint] = None
    attestation: Optional[TokenAttestation] = None

    @property
    def attested_key(self) -> Optional[str]:
        return self.session.attested_key if self.session else None

    @property
    def attested_app(self) -> Optional[AttestedApp]:
        return self.session.attested_app if self.session else None

    @property
    def blocking_signals(self) -> list:
        return [s for s in self.signals if s.blocking]

    @property
    def decision(self) -> Decision:
        if not self.ok:
            return Decision.REJECT
        if not self.device_integrity_ok or self.blocking_signals:
            return Decision.COMPROMISED
        return Decision.TRUSTWORTHY


@dataclass
class VerificationResult:
    decision: Decision
    authentic: bool
    device_integrity_ok: bool
    checks: list
    schema_version: Optional[int]
    point: Optional[str]
    ts: Optional[int]
    nonce: Optional[str]
    device: Optional[DeviceInfo]
    signals: list

    @property
    def blocking_signals(self) -> list:
        return [s for s in self.signals if s.blocking]

    @property
    def definitive_hooks(self) -> list:
        return definitive_hooks(self.signals)

    @property
    def confirmed_hook_pools(self) -> list:
        return confirmed_hook_pools(self.signals)


@dataclass
class EnrollResult:
    ok: bool
    session_id: Optional[str]
    checks: list
    reason: Optional[str]
