"""Signal resolution + enrichment parsing (Signals.kt port)."""
from .models import ResolvedSignal, DeviceInfo

ATTR_KEYS = {"path", "module_id", "needed", "links_hook_lib", "hooked_symbol", "hooked_by",
             "target", "ondisk_confirmed", "on_disk_prologue", "trampoline_class", "object",
             "base", "seals", "key", "get", "area", "hook_stub_regions", "region_count"}


def resolve(doc: dict, registry, policy) -> list:
    raw = doc.get("signals") or []
    out = []
    for s in raw:
        raw_id = s.get("id") or "INTEL_UNKNOWN"
        # Legacy prefix bridge: pre-INTEL_-rebrand builds emit SIG_-coded ids.
        sid = "INTEL_" + raw_id[4:] if raw_id.startswith("SIG_") else raw_id
        meta = registry[sid]
        severity = s.get("severity") or (meta.severity if meta else "")
        detail = s.get("detail") or ""
        attrs = parse_attrs(detail)
        blocking = policy.is_blocking(sid, severity, meta.kind if meta else None,
                                      attrs.get("hook_stub_regions") and int(attrs["hook_stub_regions"]))
        out.append(ResolvedSignal(sid, meta.detector if meta else "?", meta.kind if meta else "?",
                                  meta.title if meta else "", severity, detail, blocking, attrs))
    return out


def parse_attrs(detail: str) -> dict:
    if not detail:
        return {}
    m = {}
    for tok in detail.split(" "):
        eq = tok.find("=")
        if eq > 0:
            k = tok[:eq]
            if k in ATTR_KEYS:
                m[k] = tok[eq + 1:]
    return m


def device(doc: dict) -> DeviceInfo | None:
    d = doc.get("device")
    if not isinstance(d, dict):
        return None
    api = d.get("api")
    return DeviceInfo(int(api) if isinstance(api, (int, float)) else None,
                      d.get("abi"), d.get("model"))
