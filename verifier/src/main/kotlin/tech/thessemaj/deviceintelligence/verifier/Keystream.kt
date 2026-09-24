package tech.thessemaj.deviceintelligence.verifier

import java.security.MessageDigest

/**
 * v1 symmetric token crypto (mirrors the native encrypt_to_hex and
 * tools/server/verify_token.py):
 *
 *   key            = SHA256("intel-verdict-token-key-v1")
 *   keystream[b]   = SHA256(key || u32le(b))          // per 32-byte block
 *   plain[i]       = cipher[i] XOR keystream[block][i % 32]
 *
 * This is confidentiality + tamper-resistance in transit, NOT unforgeability —
 * the unforgeability comes from the nonce-bound hardware signature (see
 * [ChainVerifier]). The key is derived here the same way both sides derive it.
 */
internal object Keystream {
    // WIRE-CONSTANT (do NOT rebrand): unlocks the captured device fixtures under
    // src/test/resources and must stay byte-identical with the native kTokenPhrase.
    private const val PHRASE = "intel-verdict-token-key-v1"

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    /** Decrypt the ciphertext bytes to plaintext bytes. */
    fun decrypt(cipher: ByteArray): ByteArray {
        val key = sha256(PHRASE.toByteArray(Charsets.UTF_8))
        val out = ByteArray(cipher.size)
        var off = 0
        var block = 0
        while (off < cipher.size) {
            val blk = byteArrayOf(
                (block and 0xff).toByte(),
                ((block ushr 8) and 0xff).toByte(),
                ((block ushr 16) and 0xff).toByte(),
                ((block ushr 24) and 0xff).toByte(),
            )
            val ks = sha256(key, blk)
            var i = 0
            while (i < 32 && off + i < cipher.size) {
                out[off + i] = (cipher[off + i].toInt() xor ks[i].toInt()).toByte()
                i++
            }
            off += 32
            block++
        }
        return out
    }

    /** Decrypt a hex token to its UTF-8 plaintext (the signed_content + binding). */
    fun decryptHex(tokenHex: String): String =
        String(decrypt(Hex.decode(tokenHex.trim())), Charsets.UTF_8)
}

/** Minimal hex helpers (lowercase). */
internal object Hex {
    fun decode(s: String): ByteArray {
        val clean = s.trim()
        require(clean.length % 2 == 0) { "odd-length hex" }
        val out = ByteArray(clean.length / 2)
        var i = 0
        while (i < clean.length) {
            out[i / 2] = ((hexNibble(clean[i]) shl 4) or hexNibble(clean[i + 1])).toByte()
            i += 2
        }
        return out
    }

    fun encode(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4])
            sb.append("0123456789abcdef"[v and 0xf])
        }
        return sb.toString()
    }

    private fun hexNibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("bad hex char '$c'")
    }
}
