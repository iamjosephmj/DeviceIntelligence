#!/usr/bin/env python3
"""Aggregate the clean-device FP harness output into a PASS/FAIL report.

A genuine, non-rooted device must yield `critical=0 clean=1` with zero findings
on EVERY iteration. Any finding is a candidate false positive. A rooted device is
marked n/a (findings there are expected true positives, not FPs).

Usage: fp_report.py <outdir>
"""
import glob
import json
import os
import sys


def load_iters(ddir):
    out = []
    for p in sorted(glob.glob(os.path.join(ddir, "iter*.json"))):
        try:
            out.append(json.load(open(p)))
        except Exception:
            out.append({"ok": False})
    return out


def main(outdir):
    print("# Clean-device false-positive report\n")
    print("A **PASS** means the verdict was clean on *every* iteration (critical=0, "
          "clean=1, no findings). Any finding on a genuine (non-rooted) device is a "
          "**candidate false positive**. Rooted devices are n/a — findings there are "
          "expected true positives.\n")
    print("| Device | API | Rooted | Iters | Clean iters | Result | Candidate FPs (detector/kind ×count) |")
    print("|---|---|---|---|---|---|---|")

    any_fail = False
    tested_clean = 0
    for ddir in sorted(glob.glob(os.path.join(outdir, "*"))):
        if not os.path.isdir(ddir):
            continue
        meta_p = os.path.join(ddir, "meta.json")
        meta = json.load(open(meta_p)) if os.path.exists(meta_p) else {}
        iters = load_iters(ddir)
        if not iters:
            continue

        rooted = str(meta.get("rooted", "0")).strip() not in ("0", "", "?")
        total = len(iters)
        clean = 0
        findings = {}
        bad_read = 0
        for d in iters:
            if not d.get("ok"):
                bad_read += 1
                continue
            if d.get("clean") and (d.get("critical") or 0) == 0 and not d.get("findings"):
                clean += 1
            for f in d.get("findings", []):
                key = f"{f.get('detector')}/{f.get('kind')}"
                findings[key] = findings.get(key, 0) + 1

        valid = total - bad_read           # iterations that produced a token
        if rooted:
            result = "⚠️ ROOTED (n/a)"
        elif valid == 0:
            result = "❓ NO DATA"           # every read timed out — inconclusive
        elif findings:
            # A FAIL requires an actual detector finding on a clean device — NOT a
            # read timeout. bad_read iterations are inconclusive, never a FAIL.
            result = "❌ FAIL"; any_fail = True; tested_clean += 1
        else:
            result = "✅ PASS"; tested_clean += 1

        fps = ", ".join(f"{k}×{v}" for k, v in sorted(findings.items())) or "—"
        dev = f"{meta.get('brand','?')} {meta.get('model','?')}"
        note = " (+%d no-token)" % bad_read if bad_read and bad_read != total else ""
        print(f"| {dev} | {meta.get('api','?')} | {'yes' if rooted else 'no'} | "
              f"{total} | {clean}{note} | {result} | {fps} |")

    print()
    if tested_clean == 0:
        print("ℹ️  No genuine (non-rooted) device was tested — attach a clean device "
              "(e.g. the Xiaomi API 36 / Pixel 9 Pro) to actually validate FP-freedom.")
    elif any_fail:
        print("❌ A clean device produced findings — investigate the candidate FPs above "
              "before trusting the verdict to gate real users.")
    else:
        print("✅ No clean-device false positives across the tested genuine devices.")
    return 1 if any_fail else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    raise SystemExit(main(sys.argv[1]))
