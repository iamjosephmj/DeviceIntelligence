package io.ssemaj.deviceintelligence.internal

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.util.Log
import io.ssemaj.deviceintelligence.DeviceIntelligence

/**
 * Manifest-merged [ContentProvider] used purely for early initialization.
 *
 * Android instantiates content providers AFTER the application's
 * `ClassLoader` is built but BEFORE [android.app.Application.onCreate],
 * which gives us a free, app-wide hook for pre-warming DeviceIntelligence
 * without forcing the consumer to plumb us into their `Application`
 * subclass.
 *
 * What we do here is intentionally minimal:
 *  1. Trigger [System.loadLibrary] for `dicore` early via
 *     [NativeBridge] (the field-init does the load).
 *  2. Schedule a background [DeviceIntelligence.collect] pre-warm so
 *     the F10 fingerprint is decoded and APK certs are read off the
 *     cold I/O path; the report itself is dropped (no caching at this
 *     layer) but the per-detector caches (e.g.
 *     `ApkIntegrityDetector.cachedFingerprint`) populate, making
 *     subsequent `collect()` calls fast.
 *
 * Why a background thread? Collection does ZIP I/O and a few SHA-256
 * passes — fast (~tens of ms) but not zero, and we never block
 * `onCreate` because that delays Application init for every consumer.
 *
 * The provider is `exported="false"` so it's invisible outside our own
 * process, and we never override the CRUD methods.
 *
 * Authority pattern: `${applicationId}.io.ssemaj.DeviceIntelligenceInitProvider`.
 * AGP's manifest merger substitutes `${applicationId}` with the
 * consumer's actual appId, so two apps in the same device never
 * collide on this authority.
 */
internal class DeviceIntelligenceInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context ?: return false

        // Touch NativeBridge so libdicore.so loads early (before any
        // third-party SDK has a chance to load and probe us). The
        // field-init of NativeBridge does the System.loadLibrary call.
        runCatching { NativeBridge.isReady() }

        Thread({
            try {
                val report = DeviceIntelligence.collect(ctx)
                Log.i(
                    LOG_TAG,
                    "background collect pre-warm finished: " +
                        "${report.summary.totalFindings} finding(s) in ${report.collectionDurationMs}ms",
                )
            } catch (t: Throwable) {
                Log.w(LOG_TAG, "background collect pre-warm threw", t)
            }
        }, "DeviceIntelligence-Init").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY - 1
        }.start()

        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    private companion object {
        const val LOG_TAG: String = "DeviceIntelligence"
    }
}
