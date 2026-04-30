package io.ssemaj.deviceintelligence.gradle.internal

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * Compact binary serializer/deserializer for [Fingerprint].
 *
 * Format v2 (network byte order, JDK [DataOutputStream] semantics):
 *
 *   uint32  magic           = 0x52615370 ('DeviceIntelligence')
 *   uint32  formatVersion   = [FORMAT_VERSION]; bumped on wire-format change
 *   uint32  schemaVersion   = Fingerprint.SCHEMA_VERSION
 *   int64   builtAtEpochMs
 *   utf8    pluginVersion
 *   utf8    variantName
 *   utf8    applicationId
 *   uint32  signerCertCount
 *     utf8  certHex      [signerCertCount times]
 *   uint32  entryCount
 *     utf8  entryName    [entryCount times]
 *     utf8  entryHashHex [entryCount times]
 *   uint32  ignoredEntryCount
 *     utf8  name         [ignoredEntryCount times]
 *   uint32  ignoredPrefixCount
 *     utf8  prefix       [ignoredPrefixCount times]
 *   utf8    expectedSourceDirPrefix
 *   uint32  installerWhitelistCount
 *     utf8  installer    [installerWhitelistCount times]
 *   --- v2 additions below ---
 *   uint32  abiInventoryCount
 *     utf8  abi
 *     uint32 fileCount
 *       utf8 filename     [fileCount times]
 *   uint32  abiFileHashCount
 *     utf8  abi
 *     uint32 entryCount
 *       utf8 filename     [entryCount times]
 *       utf8 sha256Hex    [entryCount times]
 *   uint32  abiTextHashCount
 *     utf8  abi
 *     utf8  dicoreTextSha256Hex
 *
 * The format is intentionally trivial: no length-prefixed envelopes, no CBOR
 * tags, no varints. The runtime decoder mirrors this byte-for-byte using
 * [DataInputStream]; both ends agree on the schema purely by code inspection.
 *
 * Why not Protobuf/CBOR/MessagePack? Two reasons:
 *  1. Zero new dependencies on either side (plugin classpath stays clean,
 *     the runtime AAR doesn't pull in a 100KB serializer).
 *  2. The schema is tiny (~10 fields) and stable; the cost of a hand-rolled
 *     codec is ~30 lines per side.
 *
 * Backward compat: v1 blobs (no v2 tail) remain decodable by the runtime
 * — the decoder treats EOF after the v1 fields as "v2 fields are empty"
 * iff the formatVersion header was 1. The plugin only ever encodes
 * [FORMAT_VERSION].
 */
internal object FingerprintCodec {

    const val MAGIC: Int = 0x52615370 // 'DeviceIntelligence'

    /** Newest wire format produced by the encoder. */
    const val FORMAT_VERSION: Int = 2

    /** Minimum wire format the decoder understands. */
    const val MIN_SUPPORTED_FORMAT_VERSION: Int = 1

    fun encode(fp: Fingerprint, out: OutputStream) {
        DataOutputStream(out).run {
            writeInt(MAGIC)
            writeInt(FORMAT_VERSION)
            writeInt(fp.schemaVersion)
            writeLong(fp.builtAtEpochMs)
            writeUTF(fp.pluginVersion)
            writeUTF(fp.variantName)
            writeUTF(fp.applicationId)

            writeInt(fp.signerCertSha256.size)
            for (cert in fp.signerCertSha256) writeUTF(cert)

            // Entries are written in sorted key order so the on-disk bytes
            // are deterministic for the same logical input. This matters
            // when callers want to byte-compare two fingerprints.
            val sortedKeys = fp.entries.keys.sorted()
            writeInt(sortedKeys.size)
            for (k in sortedKeys) {
                writeUTF(k)
                writeUTF(fp.entries.getValue(k))
            }

            writeInt(fp.ignoredEntries.size)
            for (e in fp.ignoredEntries) writeUTF(e)

            writeInt(fp.ignoredEntryPrefixes.size)
            for (p in fp.ignoredEntryPrefixes) writeUTF(p)

            writeUTF(fp.expectedSourceDirPrefix)

            writeInt(fp.expectedInstallerWhitelist.size)
            for (i in fp.expectedInstallerWhitelist) writeUTF(i)

            // v2 tail. Sorted by ABI for byte-deterministic output.
            val invAbis = fp.nativeLibInventoryByAbi.keys.sorted()
            writeInt(invAbis.size)
            for (abi in invAbis) {
                writeUTF(abi)
                val files = fp.nativeLibInventoryByAbi.getValue(abi).sorted()
                writeInt(files.size)
                for (f in files) writeUTF(f)
            }

            val hashAbis = fp.nativeLibHashesByAbi.keys.sorted()
            writeInt(hashAbis.size)
            for (abi in hashAbis) {
                writeUTF(abi)
                val map = fp.nativeLibHashesByAbi.getValue(abi)
                val files = map.keys.sorted()
                writeInt(files.size)
                for (f in files) {
                    writeUTF(f)
                    writeUTF(map.getValue(f))
                }
            }

            val textAbis = fp.dicoreTextSha256ByAbi.keys.sorted()
            writeInt(textAbis.size)
            for (abi in textAbis) {
                writeUTF(abi)
                writeUTF(fp.dicoreTextSha256ByAbi.getValue(abi))
            }

            flush()
        }
    }

    fun decode(input: InputStream): Fingerprint {
        DataInputStream(input).run {
            val magic = readInt()
            require(magic == MAGIC) {
                "Fingerprint blob magic mismatch: 0x${magic.toUInt().toString(16)} != 0x52615370"
            }
            val formatVersion = readInt()
            require(formatVersion in MIN_SUPPORTED_FORMAT_VERSION..FORMAT_VERSION) {
                "Fingerprint blob format version $formatVersion not supported (expected $MIN_SUPPORTED_FORMAT_VERSION..$FORMAT_VERSION)"
            }

            val schemaVersion = readInt()
            val builtAtEpochMs = readLong()
            val pluginVersion = readUTF()
            val variantName = readUTF()
            val applicationId = readUTF()

            val certCount = readInt()
            val certs = ArrayList<String>(certCount).apply {
                repeat(certCount) { add(readUTF()) }
            }

            val entryCount = readInt()
            val entries = LinkedHashMap<String, String>(entryCount).apply {
                repeat(entryCount) {
                    val name = readUTF()
                    val hash = readUTF()
                    put(name, hash)
                }
            }

            val ignoredCount = readInt()
            val ignored = ArrayList<String>(ignoredCount).apply {
                repeat(ignoredCount) { add(readUTF()) }
            }

            val prefixCount = readInt()
            val prefixes = ArrayList<String>(prefixCount).apply {
                repeat(prefixCount) { add(readUTF()) }
            }

            val sourceDirPrefix = readUTF()

            val installerCount = readInt()
            val installers = ArrayList<String>(installerCount).apply {
                repeat(installerCount) { add(readUTF()) }
            }

            // v2 tail. Absent on v1 blobs; we leave the maps empty so
            // the runtime degrades to "no native-integrity baseline"
            // rather than failing the decode.
            var inventoryByAbi: Map<String, List<String>> = emptyMap()
            var hashesByAbi: Map<String, Map<String, String>> = emptyMap()
            var textHashByAbi: Map<String, String> = emptyMap()
            if (formatVersion >= 2) {
                val invCount = readInt()
                inventoryByAbi = LinkedHashMap<String, List<String>>(invCount).apply {
                    repeat(invCount) {
                        val abi = readUTF()
                        val fileCount = readInt()
                        val files = ArrayList<String>(fileCount).apply {
                            repeat(fileCount) { add(readUTF()) }
                        }
                        put(abi, files)
                    }
                }
                val hashAbiCount = readInt()
                hashesByAbi = LinkedHashMap<String, Map<String, String>>(hashAbiCount).apply {
                    repeat(hashAbiCount) {
                        val abi = readUTF()
                        val fileCount = readInt()
                        val files = LinkedHashMap<String, String>(fileCount).apply {
                            repeat(fileCount) {
                                val name = readUTF()
                                val hash = readUTF()
                                put(name, hash)
                            }
                        }
                        put(abi, files)
                    }
                }
                val textAbiCount = readInt()
                textHashByAbi = LinkedHashMap<String, String>(textAbiCount).apply {
                    repeat(textAbiCount) {
                        val abi = readUTF()
                        val hash = readUTF()
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
    }
}
