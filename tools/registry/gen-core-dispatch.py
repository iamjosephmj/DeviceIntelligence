#!/usr/bin/env python3
"""Generate the wired no-arg verdict-core dispatch block from the manifest.

Reads tools/registry/verdict-cores.json (the single source of truth for WHICH
no-arg cores dicore_verdict runs, and in what order) and writes the generated
macro the orchestrator invokes. The cores stay DIRECT CALLS — deliberately not
a function-pointer table, which would be a hijack target and a hookable central
dispatch in anti-tamper code. The manifest's job is to make "added a detector
but forgot to wire it" a manifest diff instead of an orchestrate.cpp diff, and
to let --check fail the build when the two drift.

    python3 tools/registry/gen-core-dispatch.py           # regenerate the header
    python3 tools/registry/gen-core-dispatch.py --check   # fail (exit 1) if stale, don't write

Run --check in CI so an edited manifest that forgot to regenerate is caught.
The header embeds a sha256 of the manifest; :deviceintelligence's
checkCoreDispatchFresh Gradle task verifies it WITHOUT needing python — same
pattern as the signal-ids freshness guard.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "verdict-cores.json")
HEADER = os.path.join(
    HERE, "..", "..", "deviceintelligence", "src", "main", "cpp", "dicore",
    "orchestrator", "core_dispatch.gen.h")


def render() -> str:
    with open(MANIFEST, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(MANIFEST) as f:
        manifest = json.load(f)
    lines = [
        "#pragma once",
        "// AUTO-GENERATED from tools/registry/verdict-cores.json by",
        "// tools/registry/gen-core-dispatch.py.",
        f"// cores-sha256: {digest}",
        "//",
        "// The digest above is of verdict-cores.json. :deviceintelligence's",
        "// checkCoreDispatchFresh task recomputes it and FAILS THE BUILD on a mismatch,",
        "// so an edited manifest can no longer ship a stale dispatch block. Regenerate",
        "// with the command above.",
        "// DO NOT EDIT. Regenerate after changing the manifest.",
        "//",
        "// Each entry is a DIRECT call (no dispatch table: in anti-tamper code a",
        "// function-pointer table is a hijack target). Appended in wire order.",
        "#define DICORE_RUN_WIRED_CORES(append, out, critical) \\",
    ]
    for c in manifest["cores"]:
        if c.get("note"):
            lines.append(f"    /* {c['note']} */ \\")
        lines.append(f"    append(out, \"{c['detector']}\", {c['call']}, critical); \\")
    # drop the trailing backslash of the last line (macro ends there)
    lines[-1] = lines[-1].rstrip("\\").rstrip()
    return "\n".join(lines) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    header = render()
    if check:
        with open(HEADER) as f:
            current = f.read()
        if current != header:
            sys.stderr.write(
                "core_dispatch.gen.h is STALE w.r.t. verdict-cores.json. "
                "Regenerate:\n    python3 tools/registry/gen-core-dispatch.py\n")
            return 1
        print("core_dispatch.gen.h is fresh")
        return 0
    with open(HEADER, "w") as f:
        f.write(header)
    print(f"wrote {HEADER} ({header.count('; \\\\') + 1} append lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
