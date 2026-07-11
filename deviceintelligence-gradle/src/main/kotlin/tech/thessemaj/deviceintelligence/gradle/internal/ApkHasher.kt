package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

/**
 * Walks an APK / ZIP and computes the SHA-256 of the COMPRESSED body bytes
 * of each entry, mirroring exactly the algorithm used by dicore's native
 * `zip_parser.cpp`. The two sides must produce identical hashes for the
 * same input, so the algorithm is intentionally a line-by-line port:
 *
 *  1. Find End-of-Central-Directory record by scanning backward from EOF.
 *  2. Read total entry count + central directory offset/size.
 *  3. For each Central Directory File Header (CDFH):
 *       - read entry name, compression method, compressed size, LFH offset
 *       - seek to LFH, read the 30-byte fixed header to get the on-disk
 *         filename + extra-field lengths
 *       - body_offset = lfh_offset + 30 + lfh_filename_len + lfh_extra_len
 *       - read [body_offset, body_offset + compressed_size) bytes
 *       - SHA-256 those raw bytes
 *
 * Skips entries whose name matches any of [ignoredEntries] (exact match) or
 * starts with any prefix in [ignoredEntryPrefixes]. Skipped entries do not
 * appear in the returned map; the runtime must apply the same filter.
 */
internal class ApkHasher(
    private val ignoredEntries: Set<String>,
    private val ignoredEntryPrefixes: List<String>,
) {

    fun walk(apk: File): LinkedHashMap<String, String> {
        require(apk.isFile) { "Not a file: $apk" }
        val out = LinkedHashMap<String, String>()
        RandomAccessFile(apk, "r").use { raf ->
            val cdi = locateCentralDirectory(raf)
            val cd = ByteArray(cdi.cdSize.toInt()).also {
                raf.seek(cdi.cdOffset)
                raf.readFully(it)
            }
            var off = 0
            for (i in 0 until cdi.totalEntries) {
                if (off + CDFH_MIN > cd.size) error("truncated central directory")
                require(rd32(cd, off) == CDFH_MAGIC) { "bad CDFH at $off" }

                val compMethod = rd16(cd, off + 10)
                val compSize   = rd32(cd, off + 20).toUInt().toLong()
                val nameLen    = rd16(cd, off + 28)
                val extraLen   = rd16(cd, off + 30)
                val cmtLen     = rd16(cd, off + 32)
                val lfhOff     = rd32(cd, off + 42).toUInt().toLong()

                val name = String(cd, off + CDFH_MIN, nameLen, Charsets.UTF_8)

                val keep = name !in ignoredEntries &&
                        ignoredEntryPrefixes.none { name.startsWith(it) }

                if (keep) {
                    if (compSize == 0xFFFF_FFFFL) {
                        // ZIP64; bail. The native side also skips these.
                        // For typical APKs this never triggers.
                    } else {
                        val bodyOff = bodyOffset(raf, lfhOff)
                        val sha = sha256Range(raf, bodyOff, compSize)
                        out[name] = sha
                        // Compression method is informational; we hash bytes
                        // as-on-disk regardless. Stash for diagnostics.
                        @Suppress("UNUSED_VARIABLE")
                        val _method = compMethod
                    }
                }

                off += CDFH_MIN + nameLen + extraLen + cmtLen
            }
        }
        return out
    }

    // -- internals --

    private data class CdInfo(val cdOffset: Long, val cdSize: Long, val totalEntries: Int)

    private fun locateCentralDirectory(raf: RandomAccessFile): CdInfo {
        val total = raf.length()
        require(total >= EOCD_MIN) { "file too small" }
        // EOCD comment is up to 0xFFFF; scan that window backward.
        val scan = minOf(total, (EOCD_MIN + 0xFFFF).toLong())
        val start = total - scan
        val window = ByteArray(scan.toInt())
        raf.seek(start)
        raf.readFully(window)
        var i = window.size - EOCD_MIN
        while (i >= 0) {
            if (rd32(window, i) == EOCD_MAGIC) {
                val totalEntries = rd16(window, i + 10)
                val cdSize       = rd32(window, i + 12).toUInt().toLong()
                val cdOffset     = rd32(window, i + 16).toUInt().toLong()
                if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL) {
                    error("ZIP64 EOCD detected, not supported in fingerprint hasher")
                }
                if (cdOffset + cdSize > total) error("CD out of range")
                return CdInfo(cdOffset, cdSize, totalEntries)
            }
            i--
        }
        error("EOCD not found")
    }

    private fun bodyOffset(raf: RandomAccessFile, lfhOff: Long): Long {
        val lfh = ByteArray(LFH_MIN)
        raf.seek(lfhOff)
        raf.readFully(lfh)
        require(rd32(lfh, 0) == LFH_MAGIC) { "bad LFH at $lfhOff" }
        val nameLen  = rd16(lfh, 26)
        val extraLen = rd16(lfh, 28)
        return lfhOff + LFH_MIN + nameLen + extraLen
    }

    private fun sha256Range(raf: RandomAccessFile, off: Long, len: Long): String {
        val md = MessageDigest.getInstance("SHA-256")
        raf.seek(off)
        val buf = ByteArray(64 * 1024)
        var remaining = len
        while (remaining > 0) {
            val want = if (remaining < buf.size) remaining.toInt() else buf.size
            val read = raf.read(buf, 0, want)
            if (read <= 0) error("unexpected EOF reading entry body at $off")
            md.update(buf, 0, read)
            remaining -= read
        }
        return md.digest().toHex()
    }

    private fun rd16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

    private fun rd32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)

    companion object {
        private const val EOCD_MAGIC = 0x06054b50
        private const val CDFH_MAGIC = 0x02014b50
        private const val LFH_MAGIC  = 0x04034b50
        private const val EOCD_MIN   = 22
        private const val CDFH_MIN   = 46
        private const val LFH_MIN    = 30
    }
}

private fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef".toCharArray()
    val out = CharArray(size * 2)
    for (i in indices) {
        out[i * 2]     = hex[(this[i].toInt() shr 4) and 0xF]
        out[i * 2 + 1] = hex[this[i].toInt() and 0xF]
    }
    return String(out)
}
