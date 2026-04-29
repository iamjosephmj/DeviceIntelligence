package io.ssemaj.deviceintelligence.internal

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.IOException

/**
 * Pulls the encrypted fingerprint blob out of the running APK, recovers
 * the per-build XOR key from the generated assembler, decrypts, and
 * decodes it back into a [Fingerprint].
 *
 * Failure modes are explicit: every distinct way the pipeline can break
 * is its own [DecodeResult.Failure] subtype so the integrity.apk detector can map
 * them to structured tampering evidence (asset stripped vs. key
 * missing vs. wrong key vs. format skew vs. corrupt blob).
 *
 * [decodeOrThrow] is provided for tests and the preview surface that
 * want the happy-path object directly; it just unwraps the same result.
 */
internal object FingerprintDecoder {

    /**
     * Run the full read -> XOR -> decode pipeline. Never throws (apart
     * from arithmetic / OOM); every recoverable failure is captured in a
     * typed [DecodeResult.Failure].
     */
    fun decode(context: Context): DecodeResult {
        val encrypted = try {
            FingerprintAssetReader.readEncryptedBytes(context)
        } catch (e: FingerprintAssetReader.AssetMissingException) {
            return DecodeResult.Failure.AssetMissing(e.message ?: "asset missing", e.apkPath, e)
        } catch (e: IOException) {
            return DecodeResult.Failure.AssetMissing(
                e.message ?: "asset I/O error",
                apkPath = context.applicationInfo.sourceDir ?: "<null>",
                cause = e,
            )
        }

        val key = try {
            KeyResolver.assembleKey()
        } catch (e: KeyResolver.KeyMissingException) {
            return DecodeResult.Failure.KeyMissing(e.message ?: "key missing", e)
        }

        val plaintext = ByteArray(encrypted.size).also { out ->
            for (i in encrypted.indices) {
                out[i] = (encrypted[i].toInt() xor key[i % key.size].toInt()).toByte()
            }
        }

        val fingerprint = try {
            FingerprintCodec.decode(ByteArrayInputStream(plaintext))
        } catch (e: FingerprintCodec.BadMagicException) {
            return DecodeResult.Failure.BadMagic(
                "fingerprint blob magic mismatch (wrong key or replaced asset)",
                e.observedMagic,
                e,
            )
        } catch (e: FingerprintCodec.UnsupportedFormatException) {
            return DecodeResult.Failure.FormatVersionMismatch(
                "fingerprint blob format ${e.observed} unsupported (runtime expects ${e.expected})",
                e.observed,
                e.expected,
                e,
            )
        } catch (e: IOException) {
            return DecodeResult.Failure.Corrupt(
                e.message ?: "fingerprint blob is corrupt",
                e,
            )
        } catch (t: Throwable) {
            return DecodeResult.Failure.Corrupt(
                "unexpected error while decoding fingerprint: ${t.javaClass.simpleName}: ${t.message}",
                t,
            )
        }

        return DecodeResult.Ok(fingerprint)
    }

    /**
     * Convenience wrapper: returns the [Fingerprint] on success, throws
     * [DecodeFailureException] otherwise. Use only where a typed result
     * isn't needed (tests, smoke checks).
     */
    fun decodeOrThrow(context: Context): Fingerprint = when (val r = decode(context)) {
        is DecodeResult.Ok -> r.fingerprint
        is DecodeResult.Failure -> throw DecodeFailureException(r)
    }

    /** Raised by [decodeOrThrow]; carries the structured [failure]. */
    class DecodeFailureException(
        val failure: DecodeResult.Failure,
    ) : RuntimeException("${failure.javaClass.simpleName}: ${failure.message}", failure.cause)
}

/**
 * Outcome of [FingerprintDecoder.decode]. Either an [Ok] carrying the
 * baked [Fingerprint], or one of the typed [Failure] subtypes.
 */
internal sealed class DecodeResult {

    data class Ok(val fingerprint: Fingerprint) : DecodeResult()

    sealed class Failure : DecodeResult() {
        abstract val message: String
        abstract val cause: Throwable?

        /** [Fingerprint.ASSET_PATH] is missing or unreadable in the base APK. */
        data class AssetMissing(
            override val message: String,
            val apkPath: String,
            override val cause: Throwable?,
        ) : Failure()

        /** Generated [KeyResolver.ASSEMBLER_FQN] is missing or broken. */
        data class KeyMissing(
            override val message: String,
            override val cause: Throwable?,
        ) : Failure()

        /** Decrypted blob doesn't start with the expected magic (wrong key). */
        data class BadMagic(
            override val message: String,
            val observedMagic: Int,
            override val cause: Throwable?,
        ) : Failure()

        /** Wire-format version skew between plugin and runtime. */
        data class FormatVersionMismatch(
            override val message: String,
            val observed: Int,
            val expected: Int,
            override val cause: Throwable?,
        ) : Failure()

        /** Truncated, malformed, or otherwise unparseable blob. */
        data class Corrupt(
            override val message: String,
            override val cause: Throwable?,
        ) : Failure()
    }
}
