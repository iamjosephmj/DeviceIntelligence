#!/usr/bin/env python3
"""F1 source-side prose gate (python3, stdlib only).

Fails (exit 1) if any C string literal in the detector verdict emitters is
>= 120 chars after joining adjacent "..." fragments (multi-line concatenation)
with comments stripped. Handles char literals ('x', '\\' etc.), raw strings
R"delim(...)delim" (incl. u8R/LR/uR/UR prefixes), escapes, and // /* */ comments.
Run: python3 tools/qa/detector-prose-check.py   (CWD-independent; silent on pass)
"""
import glob, hashlib, os, re, sys

LIMIT = 120
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GLOB = os.path.join(ROOT, "deviceintelligence", "src", "main", "cpp", "dicore", "detectors", "**", "*.cpp")
IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
RAW_PREFIX = set("uUL8")  # chars allowed before R in u8R"/LR"/uR"/UR"/R

# Not verdict prose (F1 is about explanation literals in detector verdict records):
#  9e271f3b5a9d263a — inline_prologue.cpp: mangled libart symbol, a dynsym MATCH constant
#                     (art::JavaVMExt::LoadNativeLibrary); altering it breaks the check.
#  523c9ff30e964857 — baseline.cpp: RLOGI diagnostic format string, not part of any verdict record.
ALLOW_SHA16 = {"9e271f3b5a9d263a", "523c9ff30e964857"}


def fail(msg):
    print(msg)
    sys.exit(1)


def blanked(text):  # same length, newlines kept, everything else blanked
    return "".join(ch if ch == "\n" else " " for ch in text)


files = sorted(glob.glob(GLOB, recursive=True))
if not files:
    fail(f"detector-prose-check: no detector sources found under {GLOB}")

bad = []
for path in files:
    try:
        src = open(path, encoding="utf-8").read()
    except OSError as e:
        fail(f"detector-prose-check: cannot read {path}: {e}")
    out, i, n = [], 0, len(src)
    while i < n:  # linear scan: keep string spans verbatim, blank char/raw spans, NUL out code
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i); j = n if j < 0 else j
            out.append(blanked(src[i:j])); i = j
            continue  # newline after the comment must stay visible to the line counter
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2); j = n if j < 0 else j + 2
            out.append(blanked(src[i:j])); i = j
            continue  # never consume the char following the comment (e.g. an opening quote)
        elif c == '"' and i > 0 and src[i - 1] == "R":  # raw string? walk back over u8R/LR/... prefix
            k, pfx = i - 2, ""
            while k >= 0 and src[k] in RAW_PREFIX and len(pfx) < 2:
                pfx = src[k] + pfx; k -= 1
            if k < 0 or src[k] not in IDENT:
                j = src.find("(", i + 1)
                if 0 < j - i - 1 <= 16:  # delim must be short and parenthesis-terminated
                    delim = src[i + 1:j]
                    e = src.find(")" + delim + '"', j + 1)
                    end = n if e < 0 else e + len(delim) + 2
                    out.append(blanked(src[i:end])); i = end
                    continue
        if c == '"':  # normal string literal (escapes respected)
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if j < n:
                out.append(src[i:j + 1]); i = j + 1
            else:  # unterminated: blank the rest (keeps 1:1 newline alignment)
                out.append(blanked(src[i:])); i = n
        elif c == "'":  # char literal: consume only when a closing quote appears nearby
            k = i + 1
            while k < n and src[k] != "'" and k - i <= 64:
                k += 2 if src[k] == "\\" else 1
            if k < n and src[k] == "'":
                out.append(blanked(src[i:k + 1])); i = k + 1
            else:  # digit separator / stray apostrophe: plain code
                out.append("\0"); i += 1
        else:
            out.append(c if c in " \t\r\n" else "\0"); i += 1
    stripped = "".join(out)
    for m in re.finditer(r'(?:"(?:[^"\\]|\\.)*"\s*)+', stripped):
        lit = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(0)))
        if len(lit) >= LIMIT:
            if hashlib.sha256(lit.encode()).hexdigest()[:16] in ALLOW_SHA16:
                continue  # allowlisted non-prose literal (see header)
            line = stripped.count("\n", 0, m.start()) + 1
            bad.append((os.path.relpath(path, ROOT), line, len(lit), lit[:70]))

for rel, line, ln, head in bad:
    print(f"PROSE>={LIMIT}: {rel}:{line} len={ln} :: {head}...")
if bad:
    fail(f"detector-prose-check: FAIL {len(bad)} literal(s) >= {LIMIT} chars")
