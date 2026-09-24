#!/usr/bin/env python3
"""Generate the native (detector, kind) -> INTEL_xxxx lookup from the registry.

Reads tools/registry/signals-registry.json (the single source of truth) and writes the
generated C++ header the emitter includes. The device stamps only the opaque id
onto the wire; detector/kind never leave the device.

    python3 tools/registry/gen-signal-ids.py           # regenerate the header
    python3 tools/registry/gen-signal-ids.py --check   # fail (exit 1) if stale, don't write
    python3 tools/registry/gen-signal-ids.py --table   # print the code->meaning markdown table

Run --check in CI so a new/edited signal that forgot to regenerate is caught.
The header also embeds a sha256 of the registry, which :deviceligence's
checkSignalRegistryFresh Gradle task verifies WITHOUT needing python — see
deviceintelligence/build.gradle.kts.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "signals-registry.json")
HEADER = os.path.join(
    HERE, "..", "..", "deviceintelligence", "src", "main", "cpp", "dicore",
    "orchestrator", "signal_ids.gen.h")


def render() -> str:
    with open(REGISTRY) as f:
        reg = json.load(f)
    with open(REGISTRY, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    lines = [
        "#pragma once",
        "// AUTO-GENERATED from tools/registry/signals-registry.json by",
        "// tools/registry/gen-signal-ids.py.",
        f"// registry-sha256: {digest}",
        "//",
        "// The digest above is of signals-registry.json. :deviceintelligence's",
        "// checkSignalRegistryFresh task recomputes it and FAILS THE BUILD on a mismatch,",
        "// so an edited registry can no longer ship a stale table (which would serialize",
        "// findings as INTEL_UNKNOWN). Regenerate with the command above.",
        "// DO NOT EDIT. Regenerate after changing the registry.",
        "//",
        "// Maps an internal (detector, kind) finding to the opaque wire code. Only the",
        "// code is emitted in the token; detector/kind stay on-device. An unmapped",
        "// finding returns \"INTEL_UNKNOWN\" — a loud signal that the registry is stale.",
        "#include <string>",
        "",
        "namespace dicore {",
        "",
        "inline const char* signal_id(const std::string& detector, const std::string& kind) {",
    ]
    for s in reg["signals"]:
        if s.get("status") == "retired":
            continue
        d = s["detector"].replace("\\", "\\\\").replace('"', '\\"')
        k = s["kind"].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            f'    if (detector == "{d}" && kind == "{k}") return "{s["id"]}";')
    lines += [
        '    return "INTEL_UNKNOWN";',
        "}",
        "",
        "}  // namespace dicore",
        "",
    ]
    return "\n".join(lines)


def render_table() -> str:
    with open(REGISTRY) as f:
        reg = json.load(f)
    rows = ["| Code | detector | kind | Default severity | Meaning |",
            "|---|---|---|---|---|"]
    for s in reg["signals"]:
        if s.get("status") == "retired":
            continue
        rows.append(f"| `{s['id']}` | {s['detector']} | `{s['kind']}` | "
                    f"{s['severity']} | {s['title']} |")
    return "\n".join(rows)


def main(argv) -> int:
    if "--table" in argv:
        print(render_table())
        return 0
    out = render()
    check = "--check" in argv
    existing = None
    if os.path.exists(HEADER):
        with open(HEADER) as f:
            existing = f.read()
    if check:
        if existing != out:
            print("signal_ids.gen.h is STALE — run: python3 tools/gen-signal-ids.py",
                  file=sys.stderr)
            return 1
        print("signal_ids.gen.h is up to date.")
        return 0
    with open(HEADER, "w") as f:
        f.write(out)
    n = sum(1 for s in json.load(open(REGISTRY))["signals"]
            if s.get("status") != "retired")
    print(f"wrote {os.path.relpath(HEADER)} ({n} active signals)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
