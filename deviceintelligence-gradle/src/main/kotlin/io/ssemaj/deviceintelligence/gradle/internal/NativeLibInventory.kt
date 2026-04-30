package io.ssemaj.deviceintelligence.gradle.internal

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Walks an APK's `lib/<abi>/<file>.so` entries and builds the build-time
 * native-library fingerprint that NATIVE_INTEGRITY_DESIGN.md
 * Component 1 bakes into `Fingerprint.bin`:
 *
 *   - inventory of every shipped `.so` filename, grouped by ABI
 *   - whole-file SHA-256 of every `.so`, grouped by ABI
 *   - SHA-256 of `libdicore.so`'s ELF `.text` section, per ABI
 *
 * The runtime selects the per-ABI entry matching `Build.SUPPORTED_ABIS[0]`
 * and feeds the values into `NativeBridge.initNativeIntegrity(...)`.
 *
 * Both [walkApk] (used by the diagnostic [io.ssemaj.deviceintelligence.gradle.tasks.ComputeFingerprintTask])
 * and [walkRawEntries] (used by the in-pipeline [io.ssemaj.deviceintelligence.gradle.tasks.InstrumentApkTask]
 * which already has decompressed `.so` bodies in memory) produce
 * byte-identical fingerprints — they call the same hashing helpers
 * over the same inputs.
 */
internal object NativeLibInventory {

    /** Library that integrity.runtime self-verifies via Component 3. */
    const val DICORE_LIB_NAME: String = "libdicore.so"

    /**
     * Build-time native-library facts the plugin bakes into
     * `Fingerprint.bin`. Maps are keyed by ABI string
     * (`arm64-v8a`, `x86_64`, etc); empty for ABIs that ship no
     * `.so` files.
     */
    data class NativeLibFingerprint(
        val inventoryByAbi: Map<String, List<String>>,
        val fileHashesByAbi: Map<String, Map<String, String>>,
        val dicoreTextSha256ByAbi: Map<String, String>,
    ) {
        companion object {
            val EMPTY: NativeLibFingerprint = NativeLibFingerprint(
                inventoryByAbi = emptyMap(),
                fileHashesByAbi = emptyMap(),
                dicoreTextSha256ByAbi = emptyMap(),
            )
        }
    }

    /**
     * Open the supplied APK with [ZipFile] and extract the per-ABI
     * native-lib fingerprint. Used by ComputeFingerprintTask which
     * starts from a file on disk.
     */
    fun walkApk(apk: File): NativeLibFingerprint {
        require(apk.isFile) { "Not a file: $apk" }
        val inventory = LinkedHashMap<String, MutableList<String>>()
        val fileHashes = LinkedHashMap<String, LinkedHashMap<String, String>>()
        val textHashes = LinkedHashMap<String, String>()
        ZipFile(apk).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                val parsed = parseLibPath(e.name) ?: continue
                val (abi, fileName) = parsed
                val bytes = zf.getInputStream(e).use { stream -> stream.readAllBytes() }
                ingest(abi, fileName, bytes, inventory, fileHashes, textHashes)
            }
        }
        return finalize(inventory, fileHashes, textHashes)
    }

    /**
     * Same fingerprint, but starting from already-decompressed
     * `(name -> bytes)` pairs. Used by InstrumentApkTask which has
     * to inspect the SAME entries it'll re-zip (so the fingerprint
     * binds to the post-pass-1 image, not the AGP-signed input).
     */
    fun walkRawEntries(rawEntries: Sequence<Pair<String, ByteArray>>): NativeLibFingerprint {
        val inventory = LinkedHashMap<String, MutableList<String>>()
        val fileHashes = LinkedHashMap<String, LinkedHashMap<String, String>>()
        val textHashes = LinkedHashMap<String, String>()
        for ((name, bytes) in rawEntries) {
            val parsed = parseLibPath(name) ?: continue
            val (abi, fileName) = parsed
            ingest(abi, fileName, bytes, inventory, fileHashes, textHashes)
        }
        return finalize(inventory, fileHashes, textHashes)
    }

    /**
     * Splits `lib/<abi>/<filename>` into (abi, filename), or
     * returns null if the entry name doesn't match. Subdirectories
     * under `lib/<abi>/` are ignored — Android's loader doesn't
     * pick them up, so neither do we.
     */
    internal fun parseLibPath(entryName: String): Pair<String, String>? {
        if (!entryName.startsWith("lib/")) return null
        if (!entryName.endsWith(".so")) return null
        val rest = entryName.substring("lib/".length)
        val slash = rest.indexOf('/')
        if (slash <= 0) return null
        val abi = rest.substring(0, slash)
        val fileName = rest.substring(slash + 1)
        // Skip nested paths like lib/arm64-v8a/foo/bar.so — those
        // never load via System.loadLibrary anyway.
        if ('/' in fileName) return null
        return abi to fileName
    }

    private fun ingest(
        abi: String,
        fileName: String,
        bytes: ByteArray,
        inventory: MutableMap<String, MutableList<String>>,
        fileHashes: MutableMap<String, LinkedHashMap<String, String>>,
        textHashes: MutableMap<String, String>,
    ) {
        inventory.getOrPut(abi) { ArrayList() } += fileName
        fileHashes.getOrPut(abi) { LinkedHashMap() }[fileName] = sha256Hex(bytes)
        if (fileName == DICORE_LIB_NAME) {
            // executableSegmentSha256 returns null on parse failure
            // (not a valid 64-bit LE ELF, no PF_X PT_LOAD, etc); we
            // silently skip, the runtime then sees an empty entry
            // and degrades its self-integrity check rather than
            // blocking the build.
            //
            // We hash the executable PT_LOAD segment (`p_offset ..
            // p_offset + p_filesz`) because that's exactly the
            // byte range the runtime sees from `dl_iterate_phdr`'s
            // PF_X PT_LOAD. Hashing the `.text` section instead
            // would compare different byte ranges and false-
            // positive on every clean device — see ElfParser kdoc.
            ElfParser.executableSegmentSha256(bytes)?.let { textHashes[abi] = it }
        }
    }

    private fun finalize(
        inventory: MutableMap<String, MutableList<String>>,
        fileHashes: MutableMap<String, LinkedHashMap<String, String>>,
        textHashes: MutableMap<String, String>,
    ): NativeLibFingerprint {
        // Sort entries within each ABI so the encoded bytes are
        // deterministic for byte-comparing two fingerprints from
        // semantically-identical inputs.
        val frozenInventory = LinkedHashMap<String, List<String>>().apply {
            for (abi in inventory.keys.sorted()) {
                put(abi, inventory.getValue(abi).sorted())
            }
        }
        val frozenFileHashes = LinkedHashMap<String, Map<String, String>>().apply {
            for (abi in fileHashes.keys.sorted()) {
                val sub = LinkedHashMap<String, String>()
                for (k in fileHashes.getValue(abi).keys.sorted()) {
                    sub[k] = fileHashes.getValue(abi).getValue(k)
                }
                put(abi, sub)
            }
        }
        val frozenTextHashes = LinkedHashMap<String, String>().apply {
            for (abi in textHashes.keys.sorted()) put(abi, textHashes.getValue(abi))
        }
        return NativeLibFingerprint(
            inventoryByAbi = frozenInventory,
            fileHashesByAbi = frozenFileHashes,
            dicoreTextSha256ByAbi = frozenTextHashes,
        )
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).toHex()
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
