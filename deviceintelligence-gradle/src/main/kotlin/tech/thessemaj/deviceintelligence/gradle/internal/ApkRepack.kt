package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * The deterministic APK repack used by [tech.thessemaj.deviceintelligence.gradle.tasks.InstrumentApkTask]:
 * read an APK's entries into memory (decompressed), then write them back with a
 * fixed deflater configuration so two passes over the same entries produce
 * byte-identical compressed bodies — the property that lets the fingerprint
 * hashed from pass 1 stay valid for pass 2 (which only appends the fingerprint
 * asset).
 *
 * Also owns the 16 KB page-alignment of uncompressed `.so` entries (padding in
 * the local-file-header extra field, which does not touch entry bodies and so
 * does not disturb baked hashes).
 *
 * Internal by design: the byte layout is a contract with the native verifier.
 */
internal object ApkRepack {

    data class EntryData(
        val method: Int,
        val time: Long,
        val decompressed: ByteArray,
    )

    fun readInputEntries(input: File): LinkedHashMap<String, EntryData> {
        val out = LinkedHashMap<String, EntryData>()
        ZipFile(input).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                if (e.name.startsWith(META_INF_PREFIX)) continue
                if (e.name == Fingerprint.ASSET_PATH) continue
                val bytes = zf.getInputStream(e).use { it.readBytes() }
                out[e.name] = EntryData(
                    method = if (e.method == ZipEntry.STORED) ZipEntry.STORED else ZipEntry.DEFLATED,
                    time = e.time,
                    decompressed = bytes,
                )
            }
        }
        return out
    }

    fun writeApk(
        entries: Map<String, EntryData>,
        additional: Pair<String, ByteArray>?,
        output: File,
    ) {
        // Always level 6 (DEFAULT_COMPRESSION) + DEFAULT_STRATEGY. Determinism
        // here is what makes pass-1 and pass-2 produce identical body bytes
        // for non-fingerprint entries.
        //
        // The CountingOutputStream wrapper lets us know the exact byte
        // offset of the next local-file-header before we hand the entry
        // to ZipOutputStream — required for 16 KB page-alignment of
        // STORED .so entries (see writeEntry).
        val counting = CountingOutputStream(FileOutputStream(output))
        ZipOutputStream(counting).use { zip ->
            zip.setLevel(Deflater.DEFAULT_COMPRESSION)
            for ((name, data) in entries) {
                writeEntry(zip, counting, name, data.decompressed, data.method, data.time)
            }
            if (additional != null) {
                val (name, bytes) = additional
                writeEntry(zip, counting, name, bytes, ZipEntry.STORED, time = FIXED_EPOCH_MS)
            }
        }
    }

    private fun writeEntry(
        zip: ZipOutputStream,
        counting: CountingOutputStream,
        name: String,
        data: ByteArray,
        method: Int,
        time: Long,
    ) {
        val entry = ZipEntry(name).apply {
            this.method = method
            this.time = time
            if (method == ZipEntry.STORED) {
                size = data.size.toLong()
                compressedSize = data.size.toLong()
                crc = CRC32().apply { update(data) }.value
            }
        }

        // 16 KB page-align uncompressed shared libraries so Android 15+
        // on 16 KB-page-size devices (Pixel 8a/9, API 35/36 emulators
        // with the 16 KB system image) accepts the .so for direct mmap.
        // The padding goes into the local-file-header's extra field —
        // it does NOT touch the entry body, so the post-instrumentation
        // hash that integrity.apk baked at compute time still matches the runtime
        // ZIP-entry body byte-for-byte.
        //
        // Skipped entirely for DEFLATED entries (those are decompressed
        // before mmap so per-entry alignment doesn't matter) and for
        // anything that isn't a .so (resources.arsc has its own much
        // looser alignment rules).
        if (method == ZipEntry.STORED && name.endsWith(".so")) {
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            val headerSizeBeforeExtra = LOCAL_FILE_HEADER_FIXED_SIZE + nameBytes.size
            val nextDataOffsetWithoutPad = counting.count + headerSizeBeforeExtra
            val rem = (nextDataOffsetWithoutPad % SO_ALIGNMENT).toInt()
            if (rem != 0) {
                // Standard 4-byte extra-field record header (id + size)
                // takes 4 bytes minimum. If the natural padding gap is
                // 1..3 bytes we can't fit the header → bump up to the
                // next page. Worst case wastes 16 KB once per .so;
                // negligible for any real APK.
                var padding = SO_ALIGNMENT - rem
                if (padding < EXTRA_RECORD_HEADER_BYTES) padding += SO_ALIGNMENT
                entry.extra = buildPaddingExtra(padding.toInt())
            }
        }

        zip.putNextEntry(entry)
        zip.write(data)
        zip.closeEntry()
    }

    /**
     * Builds a single well-formed extra-field record of total size
     * [totalBytes]. Uses an unassigned header id (0xCAFE) so well-behaved
     * ZIP readers (Android's PackageManager, apksig, the JDK) skip it
     * cleanly as an unknown record.
     */
    private fun buildPaddingExtra(totalBytes: Int): ByteArray {
        require(totalBytes >= EXTRA_RECORD_HEADER_BYTES) {
            "padding $totalBytes < minimum extra-record header size $EXTRA_RECORD_HEADER_BYTES"
        }
        val out = ByteArray(totalBytes)
        // Header id 0xCAFE, little-endian.
        out[0] = 0xFE.toByte()
        out[1] = 0xCA.toByte()
        // Data size (= totalBytes - 4), little-endian.
        val dataSize = totalBytes - EXTRA_RECORD_HEADER_BYTES
        out[2] = (dataSize and 0xFF).toByte()
        out[3] = ((dataSize ushr 8) and 0xFF).toByte()
        // Body bytes are already zero from ByteArray init.
        return out
    }

    /**
     * Tracks total bytes written through the wrapped stream. Required
     * for computing the byte offset of the next ZIP local-file-header
     * before ZipOutputStream commits it to disk.
     */
    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        var count: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }

    private const val META_INF_PREFIX: String = "META-INF/"

    // A constant epoch for the fingerprint asset. The on-disk LFH stores
    // this as DOS time, which doesn't affect ApkHasher (it hashes body
    // bytes, not LFH bytes), but using a constant keeps the asset's LFH
    // stable across builds — useful for diffing.
    private const val FIXED_EPOCH_MS: Long = 0L

    // ZIP local-file-header layout: 30 bytes of fixed fields, followed
    // by `name_length` bytes of filename, followed by `extra_length`
    // bytes of extra data, followed by the entry body. The extra
    // field is where 16 KB padding lives.
    private const val LOCAL_FILE_HEADER_FIXED_SIZE: Int = 30

    // Each extra-field record carries a 4-byte header (2-byte id +
    // 2-byte data length) followed by `data length` bytes of body.
    private const val EXTRA_RECORD_HEADER_BYTES: Int = 4

    // Page size we align uncompressed shared libraries to. Android
    // 15+ on devices booted with 16 KB pages requires this; 4 KB-page
    // devices tolerate the extra padding silently.
    private const val SO_ALIGNMENT: Long = 16384L
}
