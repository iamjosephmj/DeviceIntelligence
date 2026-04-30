package io.ssemaj.deviceintelligence.internal

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Runtime decoder for the binary [Fingerprint] format produced by
 * `io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec`.
 *
 * The wire format (network byte order, JDK [java.io.DataOutputStream]
 * semantics) is documented in the build-time codec; this class is the
 * other half. They MUST stay in sync byte-for-byte:
 *
 *   uint32  magic           = [MAGIC]   ('DeviceIntelligence')
 *   uint32  formatVersion   in [MIN_SUPPORTED_FORMAT_VERSION..[FORMAT_VERSION]]
 *   uint32  schemaVersion
 *   int64   builtAtEpochMs
 *   utf8    pluginVersion
 *   utf8    variantName
 *   utf8    applicationId
 *   uint32  signerCertCount + utf8[]
 *   uint32  entryCount      + (utf8 name, utf8 hashHex)[]
 *   uint32  ignoredCount    + utf8[]
 *   uint32  ignoredPrefixCount + utf8[]
 *   utf8    expectedSourceDirPrefix
 *   uint32  installerWhitelistCount + utf8[]
 *   --- v2 additions ---
 *   uint32  abiInventoryCount + (utf8 abi, uint32 fileCount, utf8 filename[])[]
 *   uint32  abiFileHashCount  + (utf8 abi, uint32 entryCount, (utf8 filename, utf8 sha)[])[]
 *   uint32  abiTextHashCount  + (utf8 abi, utf8 sha)[]
 *
 * Decode-only: the runtime never re-encodes a fingerprint, so we drop the
 * encoder half to keep the AAR small and remove the temptation to mutate
 * a baked blob.
 */
internal object FingerprintCodec {

    /** ASCII 'R','a','S','p'; matches plugin-side MAGIC. */
    const val MAGIC: Int = 0x52615370

    /** Newest wire format the decoder understands. */
    const val FORMAT_VERSION: Int = 2

    /**
     * Oldest wire format the decoder accepts. Kept at 1 so apps
     * shipped against the F18-era plugin still boot — the v2 tail
     * is treated as empty for those, which silently disables the
     * native-integrity baselines that depend on it (the runtime
     * detector reports no findings rather than crashing).
     */
    const val MIN_SUPPORTED_FORMAT_VERSION: Int = 1

    /**
     * Decode a fingerprint from [input]. Throws:
     *   - [BadMagicException] if the first 4 bytes are not [MAGIC]; the
     *     blob was either not produced by io.ssemaj or the XOR key was wrong.
     *   - [UnsupportedFormatException] if the format version is unknown;
     *     plugin and runtime are version-skewed.
     *   - [IOException] for any other framing/parse error (truncated blob,
     *     malformed UTF, etc.).
     */
    fun decode(input: InputStream): Fingerprint {
        val din = DataInputStream(input)
        val magic = din.readInt()
        if (magic != MAGIC) throw BadMagicException(magic)
        val formatVersion = din.readInt()
        if (formatVersion !in MIN_SUPPORTED_FORMAT_VERSION..FORMAT_VERSION) {
            throw UnsupportedFormatException(formatVersion, FORMAT_VERSION)
        }

        val schemaVersion = din.readInt()
        val builtAtEpochMs = din.readLong()
        val pluginVersion = din.readUTF()
        val variantName = din.readUTF()
        val applicationId = din.readUTF()

        val certCount = readNonNegative(din.readInt(), "signerCertCount")
        val certs = ArrayList<String>(certCount).apply {
            repeat(certCount) { add(din.readUTF()) }
        }

        val entryCount = readNonNegative(din.readInt(), "entryCount")
        val entries = LinkedHashMap<String, String>(entryCount).apply {
            repeat(entryCount) {
                val name = din.readUTF()
                val hash = din.readUTF()
                put(name, hash)
            }
        }

        val ignoredCount = readNonNegative(din.readInt(), "ignoredEntryCount")
        val ignored = ArrayList<String>(ignoredCount).apply {
            repeat(ignoredCount) { add(din.readUTF()) }
        }

        val prefixCount = readNonNegative(din.readInt(), "ignoredPrefixCount")
        val prefixes = ArrayList<String>(prefixCount).apply {
            repeat(prefixCount) { add(din.readUTF()) }
        }

        val sourceDirPrefix = din.readUTF()

        val installerCount = readNonNegative(din.readInt(), "installerWhitelistCount")
        val installers = ArrayList<String>(installerCount).apply {
            repeat(installerCount) { add(din.readUTF()) }
        }

        var inventoryByAbi: Map<String, List<String>> = emptyMap()
        var hashesByAbi: Map<String, Map<String, String>> = emptyMap()
        var textHashByAbi: Map<String, String> = emptyMap()
        if (formatVersion >= 2) {
            val invCount = readNonNegative(din.readInt(), "abiInventoryCount")
            inventoryByAbi = LinkedHashMap<String, List<String>>(invCount).apply {
                repeat(invCount) {
                    val abi = din.readUTF()
                    val fileCount = readNonNegative(din.readInt(), "abiFileCount[$abi]")
                    val files = ArrayList<String>(fileCount).apply {
                        repeat(fileCount) { add(din.readUTF()) }
                    }
                    put(abi, files)
                }
            }

            val hashAbiCount = readNonNegative(din.readInt(), "abiFileHashCount")
            hashesByAbi = LinkedHashMap<String, Map<String, String>>(hashAbiCount).apply {
                repeat(hashAbiCount) {
                    val abi = din.readUTF()
                    val fileCount = readNonNegative(din.readInt(), "abiHashEntryCount[$abi]")
                    val files = LinkedHashMap<String, String>(fileCount).apply {
                        repeat(fileCount) {
                            val name = din.readUTF()
                            val hash = din.readUTF()
                            put(name, hash)
                        }
                    }
                    put(abi, files)
                }
            }

            val textAbiCount = readNonNegative(din.readInt(), "abiTextHashCount")
            textHashByAbi = LinkedHashMap<String, String>(textAbiCount).apply {
                repeat(textAbiCount) {
                    val abi = din.readUTF()
                    val hash = din.readUTF()
                    put(abi, hash)
                }
            }
        }

        return Fingerprint(
            schemaVersion = schemaVersion,
            builtAtEpochMs = builtAtEpochMs,
            pluginVersion = pluginVersion,
            variantName = variantName,
            applicationId = applicationId,
            signerCertSha256 = certs,
            entries = entries,
            ignoredEntries = ignored,
            ignoredEntryPrefixes = prefixes,
            expectedSourceDirPrefix = sourceDirPrefix,
            expectedInstallerWhitelist = installers,
            nativeLibInventoryByAbi = inventoryByAbi,
            nativeLibHashesByAbi = hashesByAbi,
            dicoreTextSha256ByAbi = textHashByAbi,
        )
    }

    private fun readNonNegative(value: Int, field: String): Int {
        if (value < 0) {
            throw IOException("$field: negative count $value (corrupt blob)")
        }
        return value
    }

    /** Magic word in the blob is wrong; key was wrong or asset is not ours. */
    class BadMagicException(val observedMagic: Int) : IOException(
        "Fingerprint blob magic mismatch: 0x${observedMagic.toUInt().toString(16)} != 0x52615370"
    )

    /** Plugin wrote a wire-format we don't speak. */
    class UnsupportedFormatException(val observed: Int, val expected: Int) : IOException(
        "Fingerprint blob format version $observed not supported (expected $expected)"
    )
}
