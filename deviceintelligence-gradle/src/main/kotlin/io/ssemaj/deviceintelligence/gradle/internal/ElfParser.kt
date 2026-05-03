package io.ssemaj.deviceintelligence.gradle.internal

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.MessageDigest

/**
 * Minimal ELF parser used by the DeviceIntelligence Gradle plugin's
 * fingerprint pipeline to compute a deterministic SHA-256 of
 * `libdicore.so`'s **executable PT_LOAD segment** at build time.
 * The runtime later compares this against the live in-memory bytes
 * of that same segment (see `NATIVE_INTEGRITY_DESIGN.md` Component
 * 3, "G2 .text self-integrity").
 *
 * Why segment-level (PT_LOAD with PF_X) instead of a single section
 * (`.text`):
 *
 * The runtime cannot cheaply locate the `.text` section header at
 * load time — section headers are typically stripped from release
 * `.so`s, and even when present they describe file offsets rather
 * than load addresses. What the dynamic linker hands us via
 * `dl_iterate_phdr` is the **program-header view**: a small set of
 * PT_LOAD segments mapped at known virtual addresses. The runtime
 * therefore hashes the bytes of the PF_X PT_LOAD between
 * `dlpi_addr + p_vaddr` and `+ p_memsz`. To make the build-time
 * baseline comparable, we hash the corresponding **file bytes** of
 * the same PT_LOAD here (`p_offset .. p_offset + p_filesz`).
 *
 * For an executable segment, `p_filesz == p_memsz` always (no BSS
 * in code), and the segment is read-only after relocation, so the
 * file bytes equal the in-memory bytes byte-for-byte on every well-
 * formed device. Mismatch then unambiguously means in-memory
 * patching of executable code.
 *
 * Scope is intentionally narrow:
 *   - ELF32 (armeabi-v7a) and ELF64 (arm64-v8a, x86_64) supported
 *     for the segment hash; the historical section-level
 *     [findSection] entry point remains ELF64-only (it's a
 *     diagnostic, never on the runtime path).
 *   - Little-endian only (every Android ABI we support is LE).
 *   - Only the program-header table (for the segment hash) and the
 *     section-header table (for the historical [findSection] entry
 *     point) are walked. We do not parse symbols, relocations,
 *     dynamic tags, or anything else.
 *
 * Anything that doesn't match the above returns `null` rather than
 * throwing, so a quirky `.so` slipping into the APK can't break the
 * build — the runtime then sees an empty `dicoreTextSha256ByAbi`
 * entry and silently degrades the self-integrity check.
 */
internal object ElfParser {

    private const val EI_NIDENT: Int = 16
    private const val EI_CLASS: Int = 4
    private const val EI_DATA: Int = 5
    private const val ELF_CLASS_32: Byte = 1
    private const val ELF_CLASS_64: Byte = 2
    private const val ELF_DATA_LE: Byte = 1
    private val ELF_MAGIC: ByteArray = byteArrayOf(0x7f, 0x45, 0x4c, 0x46) // "\x7fELF"

    private const val PT_LOAD: Int = 1
    private const val PF_X: Int = 0x1

    /**
     * Locates the executable PT_LOAD segment in the supplied ELF
     * and returns SHA-256 (lowercase hex) of its file bytes
     * (`p_offset .. p_offset + p_filesz`), or null if the input
     * isn't a 64-bit LE ELF or has no executable segment.
     *
     * This is the build-time half of the G2 baseline; it's
     * deliberately the **same byte range** the runtime hashes from
     * the loaded image, so a clean device produces an exact match.
     */
    fun executableSegmentSha256(elfBytes: ByteArray): String? {
        val segment = findExecutableSegment(elfBytes) ?: return null
        if (segment.offset < 0 || segment.size < 0) return null
        val end = segment.offset + segment.size
        if (end > elfBytes.size) return null
        val md = MessageDigest.getInstance("SHA-256")
        md.update(elfBytes, segment.offset.toInt(), segment.size.toInt())
        return md.digest().toHex()
    }

    /**
     * Locates the `.text` section in the supplied ELF and returns
     * SHA-256 (lowercase hex) of its raw bytes, or null if the
     * input isn't a 64-bit LE ELF or has no `.text`.
     *
     * Retained for diagnostics only. Production code should call
     * [executableSegmentSha256] — see the kdoc on this object for
     * the rationale.
     */
    fun textSectionSha256(elfBytes: ByteArray): String? {
        val section = findSection(elfBytes, ".text") ?: return null
        if (section.offset < 0 || section.size < 0) return null
        val end = section.offset + section.size
        if (end > elfBytes.size) return null
        val md = MessageDigest.getInstance("SHA-256")
        md.update(elfBytes, section.offset.toInt(), section.size.toInt())
        return md.digest().toHex()
    }

    /**
     * Walks the program-header table and returns the first PT_LOAD
     * with PF_X set. There's exactly one in every Android `.so`
     * shipped through the NDK toolchain — code lives in a single
     * RX segment, .data / .bss in a separate RW segment.
     *
     * Dispatches on `EI_CLASS` to handle ELF32 (armeabi-v7a) and
     * ELF64 (arm64-v8a, x86_64). The two classes have different
     * header / phdr layouts — not just smaller fields, but a
     * **different field order in the program header**: 32-bit
     * places `p_flags` AFTER the size fields, 64-bit places it
     * second after `p_type`. Each class therefore has its own
     * helper to keep the parsing code unambiguous.
     */
    private fun findExecutableSegment(elfBytes: ByteArray): SegmentRef? {
        if (elfBytes.size < EI_NIDENT) return null
        for (i in ELF_MAGIC.indices) {
            if (elfBytes[i] != ELF_MAGIC[i]) return null
        }
        if (elfBytes[EI_DATA] != ELF_DATA_LE) return null
        return when (elfBytes[EI_CLASS]) {
            ELF_CLASS_64 -> findExecutableSegment64(elfBytes)
            ELF_CLASS_32 -> findExecutableSegment32(elfBytes)
            else -> null
        }
    }

    private fun findExecutableSegment64(elfBytes: ByteArray): SegmentRef? {
        // 64-bit ELF header layout (after e_ident[16]):
        //   uint16 e_type
        //   uint16 e_machine
        //   uint32 e_version
        //   uint64 e_entry
        //   uint64 e_phoff       <-- offset of program header table
        //   uint64 e_shoff
        //   uint32 e_flags
        //   uint16 e_ehsize
        //   uint16 e_phentsize   <-- size of one program header
        //   uint16 e_phnum       <-- number of program headers
        val di = DataInputStream(ByteArrayInputStream(elfBytes, EI_NIDENT, elfBytes.size - EI_NIDENT))
        di.skipBytes(2 + 2 + 4 + 8) // e_type..e_entry
        val ePhoff = di.readLongLE()
        di.skipBytes(8 + 4 + 2)     // e_shoff, e_flags, e_ehsize
        val ePhentsize = di.readShortLE().toInt() and 0xFFFF
        val ePhnum = di.readShortLE().toInt() and 0xFFFF
        if (ePhoff <= 0 || ePhentsize < 56 || ePhnum <= 0) return null

        val phtableEnd = ePhoff + ePhnum.toLong() * ePhentsize.toLong()
        if (phtableEnd > elfBytes.size) return null

        // Each 64-bit program header is 56 bytes:
        //   uint32 p_type        <-- PT_LOAD = 1
        //   uint32 p_flags       <-- PF_X = 0x1
        //   uint64 p_offset      <-- file offset
        //   uint64 p_vaddr
        //   uint64 p_paddr
        //   uint64 p_filesz      <-- bytes in the file
        //   uint64 p_memsz
        //   uint64 p_align
        for (i in 0 until ePhnum) {
            val pos = ePhoff + i.toLong() * ePhentsize.toLong()
            if (pos < 0 || pos + 56 > elfBytes.size) continue
            val pdi = DataInputStream(ByteArrayInputStream(elfBytes, pos.toInt(), ePhentsize))
            val pType = pdi.readIntLE()
            val pFlags = pdi.readIntLE()
            if (pType != PT_LOAD || (pFlags and PF_X) == 0) continue
            val pOffset = pdi.readLongLE()
            pdi.skipBytes(8 + 8) // p_vaddr, p_paddr
            val pFilesz = pdi.readLongLE()
            return SegmentRef(offset = pOffset, size = pFilesz)
        }
        return null
    }

    private fun findExecutableSegment32(elfBytes: ByteArray): SegmentRef? {
        // 32-bit ELF header layout (after e_ident[16]):
        //   uint16 e_type
        //   uint16 e_machine
        //   uint32 e_version
        //   uint32 e_entry
        //   uint32 e_phoff       <-- offset of program header table (32-bit!)
        //   uint32 e_shoff
        //   uint32 e_flags
        //   uint16 e_ehsize
        //   uint16 e_phentsize   <-- size of one program header
        //   uint16 e_phnum
        val di = DataInputStream(ByteArrayInputStream(elfBytes, EI_NIDENT, elfBytes.size - EI_NIDENT))
        di.skipBytes(2 + 2 + 4 + 4) // e_type..e_entry (e_entry is 32-bit on ELF32)
        val ePhoff = (di.readIntLE().toLong() and 0xFFFFFFFFL)
        di.skipBytes(4 + 4 + 2)     // e_shoff, e_flags, e_ehsize
        val ePhentsize = di.readShortLE().toInt() and 0xFFFF
        val ePhnum = di.readShortLE().toInt() and 0xFFFF
        if (ePhoff <= 0 || ePhentsize < 32 || ePhnum <= 0) return null

        val phtableEnd = ePhoff + ePhnum.toLong() * ePhentsize.toLong()
        if (phtableEnd > elfBytes.size) return null

        // Each 32-bit program header is 32 bytes — note the DIFFERENT
        // FIELD ORDER vs the 64-bit phdr: p_flags moves to AFTER the
        // size fields, not adjacent to p_type.
        //   uint32 p_type        <-- PT_LOAD = 1
        //   uint32 p_offset      <-- file offset
        //   uint32 p_vaddr
        //   uint32 p_paddr
        //   uint32 p_filesz      <-- bytes in the file
        //   uint32 p_memsz
        //   uint32 p_flags       <-- PF_X = 0x1 (different position from 64-bit!)
        //   uint32 p_align
        for (i in 0 until ePhnum) {
            val pos = ePhoff + i.toLong() * ePhentsize.toLong()
            if (pos < 0 || pos + 32 > elfBytes.size) continue
            val pdi = DataInputStream(ByteArrayInputStream(elfBytes, pos.toInt(), ePhentsize))
            val pType = pdi.readIntLE()
            if (pType != PT_LOAD) continue
            val pOffset = (pdi.readIntLE().toLong() and 0xFFFFFFFFL)
            pdi.skipBytes(4 + 4)        // p_vaddr, p_paddr
            val pFilesz = (pdi.readIntLE().toLong() and 0xFFFFFFFFL)
            pdi.skipBytes(4)            // p_memsz
            val pFlags = pdi.readIntLE()
            if ((pFlags and PF_X) == 0) continue
            return SegmentRef(offset = pOffset, size = pFilesz)
        }
        return null
    }

    /**
     * Parsed view of one PT_LOAD program header — just the file
     * extents (`p_offset`, `p_filesz`) we need for hashing.
     */
    data class SegmentRef(
        val offset: Long,
        val size: Long,
    )

    /**
     * Locates a section by name. Returns its byte offset within the
     * file and its size in bytes, or null if not found / not a
     * 64-bit LE ELF.
     */
    fun findSection(elfBytes: ByteArray, sectionName: String): SectionRef? {
        if (elfBytes.size < EI_NIDENT) return null
        for (i in ELF_MAGIC.indices) {
            if (elfBytes[i] != ELF_MAGIC[i]) return null
        }
        // We only support the ABIs we actually ship.
        if (elfBytes[EI_CLASS] != ELF_CLASS_64) return null
        if (elfBytes[EI_DATA] != ELF_DATA_LE) return null

        // 64-bit ELF header layout (after e_ident[16]):
        //   uint16 e_type
        //   uint16 e_machine
        //   uint32 e_version
        //   uint64 e_entry
        //   uint64 e_phoff
        //   uint64 e_shoff       <-- offset of section header table
        //   uint32 e_flags
        //   uint16 e_ehsize
        //   uint16 e_phentsize
        //   uint16 e_phnum
        //   uint16 e_shentsize   <-- size of one section header
        //   uint16 e_shnum       <-- number of section headers
        //   uint16 e_shstrndx    <-- index of the section-name string table
        val di = DataInputStream(ByteArrayInputStream(elfBytes, EI_NIDENT, elfBytes.size - EI_NIDENT))
        di.skipBytes(2 + 2 + 4 + 8 + 8) // e_type..e_phoff
        val eShoff = di.readLongLE()
        di.skipBytes(4 + 2 + 2 + 2)     // e_flags, e_ehsize, e_phentsize, e_phnum
        val eShentsize = di.readShortLE().toInt() and 0xFFFF
        val eShnum = di.readShortLE().toInt() and 0xFFFF
        val eShstrndx = di.readShortLE().toInt() and 0xFFFF
        if (eShoff <= 0 || eShentsize <= 0 || eShnum <= 0 || eShstrndx >= eShnum) return null

        // Each 64-bit section header is 64 bytes:
        //   uint32 sh_name        <-- offset into .shstrtab
        //   uint32 sh_type
        //   uint64 sh_flags
        //   uint64 sh_addr
        //   uint64 sh_offset      <-- byte offset in the file
        //   uint64 sh_size        <-- size in bytes
        //   uint32 sh_link
        //   uint32 sh_info
        //   uint64 sh_addralign
        //   uint64 sh_entsize
        val shtableEnd = eShoff + eShnum.toLong() * eShentsize.toLong()
        if (shtableEnd > elfBytes.size) return null

        val strHeader = readSectionHeader(elfBytes, eShoff, eShentsize, eShstrndx) ?: return null
        if (strHeader.offset < 0 || strHeader.size <= 0) return null
        if (strHeader.offset + strHeader.size > elfBytes.size) return null
        val strTab = ByteArray(strHeader.size.toInt())
        System.arraycopy(elfBytes, strHeader.offset.toInt(), strTab, 0, strTab.size)

        for (i in 0 until eShnum) {
            val header = readSectionHeader(elfBytes, eShoff, eShentsize, i) ?: continue
            val name = readNullTerminated(strTab, header.nameOffset) ?: continue
            if (name == sectionName) return header
        }
        return null
    }

    /**
     * Parsed view of one section header. `nameOffset` is the
     * offset into `.shstrtab` (callers usually only care about the
     * resolved string, but we keep the raw offset for diagnostics).
     */
    data class SectionRef(
        val nameOffset: Int,
        val offset: Long,
        val size: Long,
    )

    private fun readSectionHeader(
        elfBytes: ByteArray,
        shoff: Long,
        shentsize: Int,
        index: Int,
    ): SectionRef? {
        val pos = shoff + index.toLong() * shentsize.toLong()
        if (pos < 0 || pos + 24 > elfBytes.size) return null
        val di = DataInputStream(ByteArrayInputStream(elfBytes, pos.toInt(), shentsize))
        val shName = di.readIntLE()
        di.skipBytes(4 + 8 + 8)         // sh_type, sh_flags, sh_addr
        val shOffset = di.readLongLE()
        val shSize = di.readLongLE()
        return SectionRef(
            nameOffset = shName,
            offset = shOffset,
            size = shSize,
        )
    }

    private fun readNullTerminated(buf: ByteArray, offset: Int): String? {
        if (offset < 0 || offset >= buf.size) return null
        var end = offset
        while (end < buf.size && buf[end] != 0.toByte()) end++
        return String(buf, offset, end - offset, Charsets.UTF_8)
    }

    private fun DataInputStream.readIntLE(): Int {
        val b0 = read(); val b1 = read(); val b2 = read(); val b3 = read()
        return (b0 and 0xFF) or
            ((b1 and 0xFF) shl 8) or
            ((b2 and 0xFF) shl 16) or
            ((b3 and 0xFF) shl 24)
    }

    private fun DataInputStream.readShortLE(): Short {
        val b0 = read(); val b1 = read()
        return (((b0 and 0xFF) or ((b1 and 0xFF) shl 8))).toShort()
    }

    private fun DataInputStream.readLongLE(): Long {
        val lo = readIntLE().toLong() and 0xFFFFFFFFL
        val hi = readIntLE().toLong() and 0xFFFFFFFFL
        return lo or (hi shl 32)
    }

    private fun ByteArray.toHex(): String {
        val hex = "0123456789abcdef".toCharArray()
        val out = CharArray(size * 2)
        for (i in indices) {
            out[i * 2] = hex[(this[i].toInt() shr 4) and 0xF]
            out[i * 2 + 1] = hex[this[i].toInt() and 0xF]
        }
        return String(out)
    }
}
