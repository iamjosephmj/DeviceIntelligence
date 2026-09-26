"""The code-to-meaning map. The device emits only opaque INTEL_xxxx codes."""
import json, os

class SignalMeta:
    def __init__(self, sid, detector, kind, severity, title, description):
        self.id, self.detector, self.kind = sid, detector, kind
        self.severity, self.title, self.description = severity, title, description


class SignalRegistry:
    def __init__(self, by_id: dict):
        self._by_id = by_id

    def __getitem__(self, sid):
        return self._by_id.get(sid) if sid else None

    @property
    def size(self) -> int:
        return len(self._by_id)

    @staticmethod
    def from_json(text: str) -> "SignalRegistry":
        root = json.loads(text)
        by_id = {}
        for s in root.get("signals", []):
            if not isinstance(s, dict) or "id" not in s or s.get("status") == "retired":
                continue
            by_id[s["id"]] = SignalMeta(
                s["id"], s.get("detector", "?"), s.get("kind", "?"),
                s.get("severity", ""), s.get("title", ""), s.get("description", ""))
        return SignalRegistry(by_id)

    @staticmethod
    def from_resource(path: str) -> "SignalRegistry":
        with open(path, encoding="utf-8") as f:
            return SignalRegistry.from_json(f.read())

    @staticmethod
    def bundled() -> "SignalRegistry":
        p = os.path.join(os.path.dirname(__file__), "resources", "signals-registry.json")
        return SignalRegistry.from_resource(p)
