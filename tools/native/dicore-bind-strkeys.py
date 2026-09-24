#!/usr/bin/env python3
"""dicore-bind-strkeys.py — bind strenc keys to the linked image's exec digest.

Task A1 of the .so-hardening slice: per-string strenc keys become
    key = key0 XOR fold128(sha256(exec segment's first page))
at BUILD time on the LINKED artifact — the LLVM pass runs pre-link and cannot
know the exec bytes. The pass therefore encrypts with the seed-only key0 (as
always) and emits a `.dicoreobf.strtab` metadata section: 32-byte entries
    {u64 addr, u64 len, u64 key0, u64 flags}
(addr carries a linker relocation, so post-link it is the linked VA; flags
bit0 = BOUND (set by THIS tool, read by the runtime ctor), bit1 = NEVER_BIND
(set by the pass — the INTEL_0059 digest array stays seed-only so the baseline
decrypts independent of the exec digest). This tool, run POST_BUILD:

  1. computes D = fold128(sha256(file[exec_off : exec_off + min(4096, fsz)]))
     — the same first-page bytes the loader maps (exec segment carries no
     dynamic relocations), the same fold the runtime ctor applies via
     own_image::fold_digest128 / dicore_exec_text_key64();
  2. for every entry with flags==0 whose range overlaps NO dynamic relocation
     target: re-encrypts the range in place
         ct' = (ct XOR roll(key0)) XOR roll(key0 XOR D)
     and sets bit0 in its strtab flags. Overlapped or NEVER entries stay
     seed-only (fail-open demotion, reported). Re-runs bind nothing new
     (idempotent).
  3. verifies the patched ranges and the strtab itself lie OUTSIDE the exec
     segment — otherwise the digest would not be a fixed point (hard error).

The runtime contract: the pass-emitted dicore.strdec ctor computes
dicore_exec_text_key64() ONCE (its own /proc/self/maps + phdr resolution — no
loader calls: ctors run under loader locks) and decrypts each entry with
key0 when bit0 is clear, key0 XOR D when set. Honest scope (final review):
this is a split-halves scheme, not key confidentiality — key0 SHIPS in
.dicoreobf.strtab and the digest half is recomputable offline by anyone
holding the apk (read the strtab, hash the shipped exec page). What the
digest half binds is INTEGRITY: patch the exec page and every bound string
turns to garbage on-device (stacked with INTEL_0059's whole-segment verify).

    python3 tools/native/dicore-bind-strkeys.py <elf> [elf-cap-bytes]

No `.dicoreobf.strtab` (pass inactive / no strings) → no-op, exit 0.
"""
import hashlib
import os
import struct
import sys

PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
SHT_RELA = 4
SHT_REL = 9

# Relative-reloc packing (GNU DT_RELR / Android DT_ANDROID_RELR*): the packed
# addends live in RELR bitmap tables this tool does not decode, and the
# in-place RELA/REL values it reads for the strtab addr slots are ZERO until
# the loader expands them. Binding such an image would silently key against
# wrong slots — refuse loudly instead (W1).
RELR_DYN_TAGS = {
    36: "DT_RELR", 37: "DT_RELR_SZ", 38: "DT_RELR_ENT",
    0x6FFFE000: "DT_ANDROID_RELR", 0x6FFFE001: "DT_ANDROID_RELR_SZ",
    0x6FFFE002: "DT_ANDROID_RELR_ENT",
}
RELR_SHT_TYPES = {
    19: "SHT_RELR",                      # GNU RELR section
    0x6000001D: "SHT_ANDROID_REL",       # Android packed relocs (APS2)
    0x6000001E: "SHT_ANDROID_RELA",
    0x6000001F: "SHT_ANDROID_RELR",
}

FLAG_BOUND = 1
FLAG_NEVER = 2
END_MAGIC = 0x524156454E4F4246  # legacy magic — terminates a TU's entries
ENTRY_SZ = 32
KEY_PAGE = 4096


def elf_headers(data):
    """(endian, is64, phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx)."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        return (end, True,
                struct.unpack_from(end + "Q", data, 0x20)[0],
                struct.unpack_from(end + "H", data, 0x36)[0],
                struct.unpack_from(end + "H", data, 0x38)[0],
                struct.unpack_from(end + "Q", data, 0x28)[0],
                struct.unpack_from(end + "H", data, 0x3A)[0],
                struct.unpack_from(end + "H", data, 0x3C)[0],
                struct.unpack_from(end + "H", data, 0x3E)[0])
    return (end, False,
            struct.unpack_from(end + "I", data, 0x1C)[0],
            struct.unpack_from(end + "H", data, 0x2A)[0],
            struct.unpack_from(end + "H", data, 0x2C)[0],
            struct.unpack_from(end + "I", data, 0x20)[0],
            struct.unpack_from(end + "H", data, 0x2E)[0],
            struct.unpack_from(end + "H", data, 0x30)[0],
            struct.unpack_from(end + "H", data, 0x32)[0])


def phdrs(data, hdr):
    """[(p_type, p_flags, p_offset, p_vaddr, p_filesz)].

    Field offsets per the real Elf{32,64}_Phdr — note p_paddr sits between
    p_vaddr and p_filesz (the bug this replaced read p_paddr as p_filesz,
    inflating segment coverage and corrupting the VA→offset mapping).
    """
    end, is64, phoff, phentsize, phnum, *_ = hdr
    out = []
    for i in range(phnum):
        ph = phoff + i * phentsize
        if is64:
            p_type, p_flags = struct.unpack_from(end + "II", data, ph)
            off = struct.unpack_from(end + "Q", data, ph + 8)[0]
            vaddr = struct.unpack_from(end + "Q", data, ph + 0x10)[0]
            filesz = struct.unpack_from(end + "Q", data, ph + 0x20)[0]
        else:
            p_type = struct.unpack_from(end + "I", data, ph)[0]
            p_flags = struct.unpack_from(end + "I", data, ph + 0x18)[0]
            off = struct.unpack_from(end + "I", data, ph + 4)[0]
            vaddr = struct.unpack_from(end + "I", data, ph + 8)[0]
            filesz = struct.unpack_from(end + "I", data, ph + 0x10)[0]
        out.append((p_type, p_flags, off, vaddr, filesz))
    return out


def sections(data, hdr):
    """[(sh_name_str, sh_type, sh_offset, sh_size)] for every section."""
    end, is64, *_ph, shoff, shentsize, shnum, shstrndx = hdr
    out = []
    if shoff == 0 or shnum == 0:
        return out
    raw = []
    for i in range(shnum):
        base = shoff + i * shentsize
        if is64:
            nm = struct.unpack_from(end + "I", data, base)[0]
            ty = struct.unpack_from(end + "I", data, base + 4)[0]
            off = struct.unpack_from(end + "Q", data, base + 0x18)[0]
            sz = struct.unpack_from(end + "Q", data, base + 0x20)[0]
        else:
            nm = struct.unpack_from(end + "I", data, base)[0]
            ty = struct.unpack_from(end + "I", data, base + 4)[0]
            off = struct.unpack_from(end + "I", data, base + 0x10)[0]
            sz = struct.unpack_from(end + "I", data, base + 0x14)[0]
        raw.append((nm, ty, off, sz))
    nm0, _t, stroff, strsz = raw[shstrndx]
    names = data[stroff:stroff + strsz]
    for nm, ty, off, sz in raw:
        z = names.find(b"\0", nm)
        out.append((names[nm:z], ty, off, sz))
    return out


def exec_range(segs):
    """(offset, filesz) of the first PF_X PT_LOAD."""
    for t, fl, off, _va, fsz in segs:
        if t == PT_LOAD and fl & PF_X:
            return off, fsz
    raise SystemExit("no PF_X PT_LOAD segment")


def va_to_off(segs, va):
    for t, _fl, off, vaddr, filesz in segs:
        if t == PT_LOAD and vaddr <= va < vaddr + filesz:
            return off + (va - vaddr)
    return None


def fold128(sha32):
    return struct.unpack_from("<Q", sha32)[0] ^ struct.unpack_from("<Q", sha32, 8)[0]


def relr_indicators(data, hdr, segs):
    """Every RELR/packed-reloc indicator present in the image (dyn tags first,
    then section types — the section scan also catches stripped dynamics)."""
    found = {RELR_DYN_TAGS[t] for t in dynamic_tags(data, hdr, segs)
             if t in RELR_DYN_TAGS}
    found |= {RELR_SHT_TYPES[ty] for _n, ty, _o, _s in sections(data, hdr)
              if ty in RELR_SHT_TYPES}
    return sorted(found)


def dynamic_tags(data, hdr, segs):
    """DT tags of every PT_DYNAMIC (p_offset/p_filesz file range)."""
    end, is64 = hdr[0], hdr[1]
    tags = []
    for t, _fl, off, _va, fsz in segs:
        if t != PT_DYNAMIC:
            continue
        ent = 16 if is64 else 8
        fmt = end + ("QQ" if is64 else "II")
        for o in range(off, min(off + fsz, len(data)) - ent + 1, ent):
            tag, _val = struct.unpack_from(fmt, data, o)
            if tag == 0:
                break
            tags.append(tag)
    return tags


def xor_roll(ct, key):
    return bytes(b ^ ((key >> (8 * (i & 7))) & 0xFF) for i, b in enumerate(ct))


def relocs(data, hdr):
    """({r_offset: r_addend}, set(r_offset)) from SHT_RELA/SHT_REL sections.

    RELA addends resolve the strtab addr slots (in-place bytes may be zero);
    REL (arm32) addends live in-place, so the file value already is the VA.
    Both r_offset sets feed the overlap safety check. Packed Android relocs
    are not decoded — if ever encountered, extend here.
    """
    end, is64, *_ = hdr
    addends, targets = {}, set()
    for _name, ty, off, sz in sections(data, hdr):
        if ty not in (SHT_RELA, SHT_REL) or off == 0:
            continue
        for o in range(0, sz, 24 if (is64 and ty == SHT_RELA) else (16 if is64 else 8)):
            if is64:
                if ty == SHT_RELA:
                    r_off, _info, r_add = struct.unpack_from(end + "QQq", data, off + o)
                else:
                    r_off, _info = struct.unpack_from(end + "QQ", data, off + o)
                    r_add = None
            else:
                if ty == SHT_RELA:
                    r_off, _info, r_add = struct.unpack_from(end + "IIi", data, off + o)
                else:
                    r_off, _info = struct.unpack_from(end + "II", data, off + o)
                    r_add = None
            targets.add(r_off)
            if r_add is not None:
                addends.setdefault(r_off, r_add)
    return addends, targets


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) == 3 else 512 * 1024 * 1024
    size = os.path.getsize(path)
    if size > cap:
        raise SystemExit(f"{path}: {size} bytes exceeds cap {cap} — refusing")
    with open(path, "rb") as f:
        buf = bytearray(f.read())

    hdr = elf_headers(bytes(buf))
    is64 = hdr[1]
    segs = phdrs(bytes(buf), hdr)
    # Unconditional refuse-guard (W1): fires BEFORE the no-strtab no-op so a
    # packed binary is never silently "nothing to bind".
    relr = relr_indicators(bytes(buf), hdr, segs)
    if relr:
        raise SystemExit(
            f"{path}: relative-reloc packing present ({', '.join(relr)}) — "
            "RELR/ANDROID_RELR addends are not readable from RELA/REL sections; "
            "binding would key against wrong slots. Refusing. Relink without "
            "-z pack-relative-relocs / Android packed relocs.")
    tabs = [(off, sz) for name, _ty, off, sz in sections(bytes(buf), hdr)
            if name == b".dicoreobf.strtab"]
    if not tabs:
        print(f"dicore strkey-bind: no .dicoreobf.strtab in {os.path.basename(path)} "
              f"— nothing to bind (pass inactive or no strings)")
        return

    addends, targets = relocs(bytes(buf), hdr)
    # addr slots are relocation targets: RELA keeps the linked VA in r_addend
    # (in-place bytes may be zero), REL stores it in place. Resolve from the
    # addends when present and normalize the slot in-file (the loader applies
    # base+addend regardless — RELA ignores the stored bytes, REL holds the
    # same value), so the strtab is self-describing for artifact checks.
    # The addr field is a TYPED POINTER (see the obfuscating toolchain): u64 on ELF64,
    # u32 (padded to offset 8) on ELF32.
    fmt_addr = "<Q" if is64 else "<I"
    slot_addend = {}
    for r_off, r_add in addends.items():
        fo = va_to_off(segs, r_off)
        if fo is not None:
            slot_addend[fo] = r_add
    ex_off, ex_fsz = exec_range(segs)
    page_len = min(KEY_PAGE, ex_fsz)
    d64 = fold128(hashlib.sha256(bytes(buf[ex_off:ex_off + page_len])).digest())
    ex_end = ex_off + ex_fsz

    bound = demoted = never = already = markers = 0
    for tab_off, tab_sz in tabs:
        if tab_off < ex_end and tab_off + tab_sz > ex_off:
            raise SystemExit(f"{path}: .dicoreobf.strtab overlaps the exec segment — "
                             f"digest fixed point impossible; refusing")
        if tab_sz % ENTRY_SZ:
            raise SystemExit(f"{path}: strtab size {tab_sz} not a multiple of {ENTRY_SZ}")
        for k in range(0, tab_sz - ENTRY_SZ + 1, ENTRY_SZ):
            e = tab_off + k
            addr = struct.unpack_from(fmt_addr, buf, e)[0]
            ln, key0, flags = struct.unpack_from("<QQQ", buf, e + 8)
            if addr == 0 and flags == END_MAGIC:
                markers += 1
                continue
            if flags & ~(FLAG_BOUND | FLAG_NEVER):
                raise SystemExit(f"{path}: strtab entry {k//ENTRY_SZ}: unknown flags {flags:#x}")
            if e in slot_addend:  # normalize the addr slot to the linked VA
                addr = slot_addend[e]
                struct.pack_into(fmt_addr, buf, e, addr)
            if addr == 0:
                raise SystemExit(f"{path}: strtab entry {k//ENTRY_SZ}: null addr before marker")
            if flags & FLAG_NEVER:
                never += 1
                continue
            if flags & FLAG_BOUND:
                already += 1
                continue
            fo = va_to_off(segs, addr)
            if fo is None or fo + ln > len(buf):
                raise SystemExit(f"{path}: strtab entry {k//ENTRY_SZ}: range "
                                 f"addr={addr:#x} len={ln} not inside the file")
            if fo < ex_end and fo + ln > ex_off:
                raise SystemExit(f"{path}: strtab entry {k//ENTRY_SZ}: range overlaps "
                                 f"the exec segment — re-encrypting would move the digest")
            # relocation safety: the loader must never patch inside the range
            if any(addr <= t < addr + ln for t in targets):
                demoted += 1
                continue
            pt = xor_roll(bytes(buf[fo:fo + ln]), key0)
            buf[fo:fo + ln] = xor_roll(pt, key0 ^ d64)
            struct.pack_into("<Q", buf, e + 24, flags | FLAG_BOUND)
            bound += 1

    if bound and markers == 0:
        raise SystemExit(f"{path}: entries but no end marker — strtab corrupt; refusing")
    with open(path, "wb") as f:
        f.write(buf)
    print(f"dicore strkey-bind: bound {bound} ranges (already {already}, never {never}, "
          f"reloc-demoted {demoted}, markers {markers}) digest128={d64:016x} page={page_len}B")


if __name__ == "__main__":
    main()
