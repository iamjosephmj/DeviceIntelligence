package tech.thessemaj.deviceintelligence.gradle.internal

import java.security.MessageDigest

/**
 * Lowercase hex encoding shared by every hasher in the plugin (APK entries,
 * signer certs, ELF sections, native-lib inventories) so the encoding — and
 * therefore the strings the runtime's native parser compares against — has
 * exactly one home.
 */
internal fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef".toCharArray()
    val out = CharArray(size * 2)
    for (i in indices) {
        out[i * 2] = hex[(this[i].toInt() shr 4) and 0xF]
        out[i * 2 + 1] = hex[this[i].toInt() and 0xF]
    }
    return String(out)
}

/** SHA-256 of [bytes], lowercase hex. */
internal fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
