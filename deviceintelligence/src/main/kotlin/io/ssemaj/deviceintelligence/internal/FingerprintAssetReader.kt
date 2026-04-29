package io.ssemaj.deviceintelligence.internal

import android.content.Context
import java.io.IOException
import java.util.zip.ZipFile

/**
 * Reads the encrypted fingerprint blob that
 * `io.ssemaj.deviceintelligence.gradle.tasks.InstrumentApkTask` injected at
 * [Fingerprint.ASSET_PATH] inside the installed APK.
 *
 * We deliberately go through [ZipFile] (against
 * [android.content.pm.ApplicationInfo.sourceDir]) instead of
 * [android.content.res.AssetManager.open] for two reasons:
 *
 *  1. The asset is added by our own post-AGP transform, so it is
 *     guaranteed present in the APK ZIP, but it is NOT registered in any
 *     AAPT-generated metadata. ZipFile reads from the on-disk APK
 *     directly, side-stepping any AssetManager indexing edge cases.
 *  2. Going via the APK path lets us see exactly which file the OS thinks
 *     is our base.apk, which matters for split-APK / sourceDir spoofing
 *     checks the integrity.apk detector will run.
 */
internal object FingerprintAssetReader {

    /**
     * Returns the raw (still XOR-encrypted) bytes of the fingerprint blob
     * embedded in [context]'s base APK.
     *
     * Throws [AssetMissingException] if the APK has no such entry; that's
     * a strong tampering signal (someone stripped or replaced our asset)
     * and the integrity.apk detector treats it as a hard failure.
     */
    fun readEncryptedBytes(context: Context): ByteArray {
        val apkPath = context.applicationInfo.sourceDir
            ?: throw AssetMissingException("ApplicationInfo.sourceDir is null", apkPath = "<null>")
        val apk = try {
            ZipFile(apkPath)
        } catch (io: IOException) {
            throw AssetMissingException(
                "Failed to open base APK at $apkPath: ${io.message}",
                apkPath = apkPath,
                cause = io,
            )
        }
        return apk.use { zf ->
            val entry = zf.getEntry(Fingerprint.ASSET_PATH)
                ?: throw AssetMissingException(
                    "APK has no ${Fingerprint.ASSET_PATH} entry",
                    apkPath = apkPath,
                )
            zf.getInputStream(entry).use { it.readBytes() }
        }
    }

    /** Asset is missing or unreadable; cause is preserved for diagnostics. */
    class AssetMissingException(
        message: String,
        val apkPath: String,
        cause: Throwable? = null,
    ) : IOException(message, cause)
}
