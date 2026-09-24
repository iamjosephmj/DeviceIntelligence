#!/usr/bin/env bash
# artifact-sweep.sh — intel sweep of a linked .so (red-team regression gate).
#
# TWO-LAYER gate, matching the attacker model proven in the 2026-09-10
# red-team session: the offline attacker decrypts .dicoreobf.strtab (key0
# ships in the table itself and the digest half is recomputable from the
# shipped exec page — design finding F1), so "encrypted" is NOT
# "unrecoverable".
#
#   layer 1 — cleartext: fails when attacker-recoverable intel sits OUTSIDE
#     .dicoreobf.strtab in plaintext: (a) registry description n-grams
#     (detector evasion prose), (b) anti-analysis path/tool patterns.
#     Strings enter the image only if compiled in, so whole-file absence is
#     the correct predicate regardless of pass coverage — anything inside
#     .dicoreobf.strtab is encrypted, everything else is world-readable.
#   layer 2 — decrypted: recovers the strtab plaintext OFFLINE (no
#     execution; same algorithm as tools/native/dicore-bind-strkeys.py:
#     D = fold128(sha256(first min(4096,fsz) bytes of the PF_X PT_LOAD)),
#     per-entry key = key0 ^ D when FLAG_BOUND else key0) and runs the
#     registry-prose check against the recovered plaintext — the layer the
#     attacker actually reaches. RELA addends resolve addr slots the linker
#     zeroed.
#     Patterns are deliberately layer-1 ONLY: detector probe vocabulary
#     (frida, magisk, /proc paths) must exist somewhere in the image for
#     the detectors to detect, and the accepted split-halves threat model
#     explicitly tolerates offline recovery of the at-rest-encrypted strtab
#     (the obfuscating toolchain "honest scope") — flagging recovered probe strings kept
#     this gate permanently red on every real artifact (2026-09-10
#     acceptance ruling). Evasion PROSE has no such reason to exist anywhere
#     in the binary, so it is checked in BOTH layers.
#
# Fail-closed: any tooling failure in a layer (python crash, truncated
# input, missing summary line) exits 2 — a gate must never PASS because its
# tooling broke.
#
# Usage:
#   artifact-sweep.sh <lib.so>                    # cleartext patterns + decrypt machinery
#   artifact-sweep.sh <lib.so> --registry        # + registry prose sweep (both layers)
# Exit 0 clean, 1 leak(s) found, 2 usage/tooling error.
set -uo pipefail
[ $# -lt 1 ] && { echo "usage: artifact-sweep.sh <lib.so> [--registry]"; exit 2; }
SO="$1"
[ -f "$SO" ] || { echo "artifact-sweep: no such file: $SO"; exit 2; }
REG="$(cd "$(dirname "$0")/../registry" && pwd)/signals-registry.json"
HITS=0

report() { echo "LEAK  $*"; HITS=$((HITS + 1)); }

pats=( '/proc/self' '/proc/1' '/system/bin/su' '/system/xbin/su' \
       '/sbin/.magisk' '/data/adb/magisk' 'magisk_daemon' \
       'frida' 'xposed' 'zygisk' 'substrate' 'sandhook' 'shadowhook' \
       'bytehook' 'topjohnwu' )

# layer 1a — intel patterns, cleartext. Case-insensitive where the token is a
# name, exact where it is a path prefix. Kept deliberately small: every entry
# must be a string NO legitimate .so section name or libc import ever contains.
for pat in "${pats[@]}"; do
  if grep -aqi -- "$pat" "$SO"; then report "pattern '$pat' present in cleartext"; fi
done

# layer 1b — registry prose, cleartext: first 40 chars of every description,
# byte-exact. Crash (rc>=2) fails closed; rc==1 (leaks) counts as before.
if [ "${2:-}" = "--registry" ]; then
  command -v python3 >/dev/null || { echo "artifact-sweep: python3 required for --registry"; exit 2; }
  prose_out="$(python3 - "$REG" "$SO" <<'EOF'
import json, sys

try:
    reg, so = sys.argv[1], sys.argv[2]
    data = open(so, "rb").read()
    bad = 0
    for s in json.load(open(reg))["signals"]:
        d = s.get("description", "")
        if len(d) < 40:
            continue
        if d[:40].encode() in data:
            print(f"LEAK  prose {s['id']}: {d[:60]}...")
            bad += 1
    sys.exit(1 if bad else 0)
except SystemExit:
    raise
except Exception as e:
    print(f"artifact-sweep: registry prose layer error: {e}", file=sys.stderr)
    sys.exit(2)
EOF
)"
  rc=$?
  [ -n "$prose_out" ] && printf '%s\n' "$prose_out"
  case "$rc" in
    0) : ;;
    1) HITS=$((HITS + 1)) ;;
    *) echo "artifact-sweep: registry prose layer failed (rc=$rc)"; exit 2 ;;
  esac
fi

# layer 2 — offline-decrypted .dicoreobf.strtab: run the registry prose check
# against the plaintext an offline attacker recovers (patterns are layer-1
# only — see header). Fail-closed: rc>=2 exits 2; rc==1 must carry the
# SWEEP-DECRYPT summary AND at least one LEAK line, else it is tooling
# breakage, not a finding.
command -v python3 >/dev/null || { echo "artifact-sweep: python3 required"; exit 2; }
dec_out="$(python3 - "$SO" "${2:-}" "$REG" <<'EOF'
import hashlib, json, struct, sys

def main():
    so, mode, reg = sys.argv[1], sys.argv[2], sys.argv[3]
    data = open(so, "rb").read()

    PT_LOAD, PF_X, SHT_RELA, SHT_REL = 1, 1, 4, 9
    FLAG_BOUND, FLAG_NEVER = 1, 2
    ENTRY_SZ = 32
    END_FLAGS = (0x524156454E4F4246, 0xFFFFFFFFFFFFFFFF)

    if len(data) < 64 or data[:4] != b"\x7fELF":
        print("NOTE  decrypted layer skipped: not an ELF")
        return 0

    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"

    def u(fmt, off):
        return struct.unpack_from(end + fmt, data, off)

    phoff, phentsize, phnum = (u("Q", 0x20)[0], u("H", 0x36)[0], u("H", 0x38)[0]) if is64 \
        else (u("I", 0x1C)[0], u("H", 0x2A)[0], u("H", 0x2C)[0])
    shoff, shentsize, shnum, shstrndx = (u("Q", 0x28)[0], u("H", 0x3A)[0], u("H", 0x3C)[0], u("H", 0x3E)[0]) if is64 \
        else (u("I", 0x20)[0], u("H", 0x2E)[0], u("H", 0x30)[0], u("H", 0x32)[0])

    segs = []
    for i in range(phnum):
        ph = phoff + i * phentsize
        if is64:
            t, fl = u("II", ph)
            off, va = u("QQ", ph + 8)
            fsz = u("Q", ph + 0x20)[0]
        else:
            t = u("I", ph)[0]
            fl = u("I", ph + 0x18)[0]
            off, va, fsz = u("II", ph + 4)[0], u("I", ph + 8)[0], u("I", ph + 0x10)[0]
        segs.append((t, fl, off, va, fsz))

    raw = []
    for i in range(shnum):
        b = shoff + i * shentsize
        nm, ty = u("II", b)
        off, sz = u("QQ", b + 0x18) if is64 else (u("I", b + 0x10)[0], u("I", b + 0x14)[0])
        raw.append((nm, ty, off, sz))
    if shoff and shnum:
        stroff, strsz = raw[shstrndx][2], raw[shstrndx][3]
        names = data[stroff:stroff + strsz]
        secs = [(names[nm:names.find(b"\0", nm)], ty, off, sz) for nm, ty, off, sz in raw]
    else:
        secs = []

    def va_to_off(va):
        for t, _fl, off, vaddr, filesz in segs:
            if t == PT_LOAD and vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    ex = next(((off, fsz) for t, fl, off, _va, fsz in segs if t == PT_LOAD and fl & PF_X), None)
    if ex is None:
        print("NOTE  decrypted layer skipped: no PF_X PT_LOAD")
        return 0
    ex_off, ex_fsz = ex
    digest = hashlib.sha256(data[ex_off:ex_off + min(4096, ex_fsz)]).digest()
    D = struct.unpack_from("<Q", digest)[0] ^ struct.unpack_from("<Q", digest, 8)[0]

    addends = {}
    for _nm, ty, off, sz in secs:
        if ty not in (SHT_RELA, SHT_REL) or off == 0:
            continue
        entsz = (24 if ty == SHT_RELA else 16) if is64 else (12 if ty == SHT_RELA else 8)
        for o in range(0, sz - entsz + 1, entsz):
            if is64:
                r_off, _info = u("QQ", off + o)
                r_add = u("q", off + o + 16)[0] if ty == SHT_RELA else None
            else:
                r_off, _info = u("II", off + o)
                r_add = u("i", off + o + 8)[0] if ty == SHT_RELA else None
            if r_add is not None:
                fo = va_to_off(r_off)
                if fo is not None:
                    addends.setdefault(fo, r_add)

    tabs = [(off, sz) for nm, _ty, off, sz in secs if nm == b".dicoreobf.strtab"]
    if not tabs:
        print("NOTE  decrypted layer skipped: no .dicoreobf.strtab (pass inactive)")
        return 0

    fmt_addr = "Q" if is64 else "I"
    plain = bytearray()
    n_dec = n_print = n_never = n_unresolved = 0
    for tab_off, tab_sz in tabs:
        for k in range(0, tab_sz - ENTRY_SZ + 1, ENTRY_SZ):
            e = tab_off + k
            addr = u(fmt_addr, e)[0]
            ln, key0, flags = u("QQQ", e + 8)
            if addr == 0 and flags in END_FLAGS:
                continue
            if flags & FLAG_NEVER:
                n_never += 1
                continue
            if addr == 0:
                addr = addends.get(e, 0)
            if addr == 0:
                n_unresolved += 1
                continue
            fo = va_to_off(addr)
            if fo is None or fo + ln > len(data):
                continue
            key = key0 ^ D if flags & FLAG_BOUND else key0
            pt = bytes(b ^ ((key >> (8 * (i & 7))) & 0xFF) for i, b in enumerate(data[fo:fo + ln]))
            plain += pt
            n_dec += 1
            body = pt.rstrip(b"\x00")
            if pt.endswith(b"\x00") and len(body) >= 4 and all(32 <= c < 127 for c in body):
                n_print += 1

    bad = 0
    if mode == "--registry":
        for s in json.load(open(reg))["signals"]:
            d = s.get("description", "")
            if len(d) >= 40 and d[:40].encode() in plain:
                print(f"LEAK  decrypted prose {s['id']}: {d[:60]}...")
                bad += 1
    print(f"NOTE  SWEEP-DECRYPT: {n_dec} entries decrypted ({n_print} printable C strings), "
          f"{n_never} NEVER_BIND skipped, {n_unresolved} unresolved")
    return 1 if bad else 0

try:
    sys.exit(main())
except SystemExit:
    raise
except Exception as e:
    print(f"artifact-sweep: decrypted layer error: {e}", file=sys.stderr)
    sys.exit(2)
EOF
)"
rc=$?
[ -n "$dec_out" ] && printf '%s\n' "$dec_out"
case "$rc" in
  0) : ;;
  1)
    if ! printf '%s\n' "$dec_out" | grep -q 'SWEEP-DECRYPT'; then
      echo "artifact-sweep: decrypted layer exited 1 with no summary — tooling failure"; exit 2
    fi
    n="$(printf '%s\n' "$dec_out" | grep -c '^LEAK' || true)"
    if [ "$n" -eq 0 ]; then
      echo "artifact-sweep: decrypted layer exited 1 with no LEAK lines — tooling failure"; exit 2
    fi
    HITS=$((HITS + n))
    ;;
  *)
    echo "artifact-sweep: decrypted layer failed (rc=$rc)"; exit 2
    ;;
esac

if [ "$HITS" -eq 0 ]; then echo "PASS  artifact-sweep ($SO)"; exit 0; fi
echo "FAIL  artifact-sweep: $HITS leak(s) in $SO"; exit 1
