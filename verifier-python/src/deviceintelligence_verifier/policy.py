"""Server-side policy — the false-positive tuning that lives OFF the device."""
from dataclasses import dataclass, field

@dataclass
class Policy:
    block_severities: set = field(default_factory=lambda: {"CRITICAL"})
    allow: set = field(default_factory=set)
    block: set = field(default_factory=set)
    require_strong_box: bool = False
    max_patch_age_days: int = 365
    observe_unconfirmed_rwx: bool = False

    def is_blocking(self, sid: str = None, severity: str = None,
                    kind: str = None, hook_stub_regions: int = None) -> bool:
        if sid is not None and sid in self.allow:
            return False
        if sid is not None and sid in self.block:
            return True
        if kind == "rwx_memory_mapping" and (hook_stub_regions or 0) > 0:
            return True
        if self.observe_unconfirmed_rwx and kind == "rwx_memory_mapping" and (hook_stub_regions or 0) == 0:
            return False
        return (severity or "").upper() in self.block_severities
