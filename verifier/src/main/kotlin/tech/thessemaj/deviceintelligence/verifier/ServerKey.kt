package tech.thessemaj.deviceintelligence.verifier

import java.io.InputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Loads the backend's X25519 private half — the key that opens v2 scan tokens.
 *
 * Exists because `KeyFactory.getInstance("XDH")` is NOT universally available:
 * Android's Conscrypt only exposes it on recent releases, and this library is
 * expected to run in-process in an app at our API 28 (Android 9) floor as well as on
 * a backend JVM. Callers should use this instead of KeyFactory directly, so the
 * fallback is applied in one place.
 */
object ServerKey {

    /** DER PKCS#8 (the bytes inside a `-----BEGIN PRIVATE KEY-----` block). */
    fun fromPkcs8(der: ByteArray): PrivateKey = try {
        KeyFactory.getInstance("XDH").generatePrivate(PKCS8EncodedKeySpec(der))
    } catch (_: NoSuchAlgorithmException) {
        TokenCryptoV2.rawX25519PrivateKey(TokenCryptoV2.scalarFromPkcs8(der))
    }

    /** A `-----BEGIN PRIVATE KEY-----` PEM block, whitespace-insensitive. */
    fun fromPem(pem: String): PrivateKey = fromPkcs8(
        Base64.getDecoder().decode(
            pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace(Regex("\\s"), "")
        )
    )

    /**
     * PEM or raw DER PKCS#8 read from [source], which is CLOSED before returning.
     *
     * This is the entry point on-device: `resources.openRawResource(R.raw.…)` on
     * Android, `File(…).inputStream()` on a backend. The verifier cannot resolve a
     * key *name* for the caller — it has no Android on its classpath, so an
     * `R.raw` id means nothing to it — but a stream is something both worlds can
     * hand over, and everything after that is ours.
     */
    fun from(source: InputStream): PrivateKey {
        val bytes = source.use { it.readBytes() }
        // Cached on a digest of the material, not the array: repeated scans on a
        // backend would otherwise re-parse the same key on every request, and a
        // ByteArray key would never hit (identity equality).
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return cache.getOrPut(digest.toHexKey()) { parse(bytes) }
    }

    private val cache = ConcurrentHashMap<String, PrivateKey>()

    private fun ByteArray.toHexKey(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) sb.append("0123456789abcdef"[(b.toInt() shr 4) and 0xf])
            .append("0123456789abcdef"[b.toInt() and 0xf])
        return sb.toString()
    }

    /** PEM if it carries the armour, otherwise raw DER. */
    private fun parse(bytes: ByteArray): PrivateKey {
        val text = String(bytes, Charsets.US_ASCII)
        return if (text.contains("-----BEGIN")) fromPem(text) else fromPkcs8(bytes)
    }
}
