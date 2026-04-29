package io.ssemaj.deviceintelligence.internal

import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import android.content.Context

/**
 * `integrity.apk` — APK integrity detector.
 *
 * Compares the live, on-disk APK against the build-time
 * [Fingerprint] baked into it by the DeviceIntelligence Gradle plugin. Any
 * structural divergence becomes a [Finding]; a clean run produces
 * an empty findings list and OK status.
 *
 * Failure-mode policy:
 *  - [Fingerprint] decode failures that look like *attack* (asset
 *    stripped, key class missing, blob encrypted with a different
 *    key, blob structurally corrupt) become CRITICAL [Finding]s of
 *    OK status, not INCONCLUSIVE — those are signals worth
 *    reporting even if we can't run the rest of the comparison.
 *  - Decode failures that look like *configuration / version skew*
 *    (newer plugin produced a blob the AAR doesn't understand)
 *    become INCONCLUSIVE — that's a CI bug, not an attack.
 *  - Native lib not loaded or APK unreadable becomes INCONCLUSIVE.
 *
 * Caches the decoded [Fingerprint] for one process lifetime so the
 * surrounding [TelemetryCollector] can reuse it when populating
 * [io.ssemaj.deviceintelligence.AppContext] without re-running the whole pipeline.
 */
internal class ApkIntegrityDetector : Detector {

    override val id: String = "integrity.apk"

    @Volatile
    private var cachedFingerprint: Fingerprint? = null

    /**
     * Returns the decoded fingerprint if a successful evaluation
     * has happened in this process. Used by [TelemetryCollector]
     * to populate [io.ssemaj.deviceintelligence.AppContext.buildVariant] and
     * [io.ssemaj.deviceintelligence.AppContext.libraryPluginVersion].
     */
    fun lastDecodedFingerprint(): Fingerprint? = cachedFingerprint

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        val context = ctx.applicationContext

        // 1. Decode baked fingerprint. Some failures map to findings
        //    (genuine attack signals); some map to inconclusive.
        val baked = when (val r = FingerprintDecoder.decode(context)) {
            is DecodeResult.Ok -> {
                cachedFingerprint = r.fingerprint
                r.fingerprint
            }
            is DecodeResult.Failure -> return decodeFailureToReport(r, dur())
        }

        // 2. Native walker is mandatory.
        if (!ctx.nativeReady) {
            return inconclusive(
                id = id,
                reason = "native_not_ready",
                message = "dicore native lib not loaded: " +
                    (NativeBridge.loadError()?.message ?: "<no error captured>"),
                durationMs = dur(),
            )
        }

        val apkPath = context.applicationInfo.sourceDir
            ?: return inconclusive(
                id = id,
                reason = "apk_unreadable",
                message = "ApplicationInfo.sourceDir is null",
                durationMs = dur(),
            )

        val runtimeCerts = NativeBridge.apkSignerCertHashes(apkPath)
            ?: return inconclusive(
                id = id,
                reason = "apk_unreadable",
                message = "apkSignerCertHashes returned null for $apkPath",
                durationMs = dur(),
            )

        val runtimeEntriesArr = NativeBridge.apkEntries(apkPath)
            ?: return inconclusive(
                id = id,
                reason = "apk_unreadable",
                message = "apkEntries returned null for $apkPath",
                durationMs = dur(),
            )
        val runtimeEntries = parseEntryArray(runtimeEntriesArr)

        // 3. Diff. Findings stack independently.
        val findings = ArrayList<Finding>(4)
        val expectedCerts = baked.signerCertSha256.toSet()
        val observedCerts = runtimeCerts.toSet()
        if (observedCerts != expectedCerts) {
            findings += Finding(
                kind = "apk_signer_mismatch",
                severity = Severity.CRITICAL,
                subject = context.packageName,
                message = "APK signer cert(s) differ from the build-time baked set",
                details = mapOf(
                    "expected" to baked.signerCertSha256.joinToString(","),
                    "observed" to runtimeCerts.joinToString(","),
                ),
            )
        }

        if (!apkPath.startsWith(baked.expectedSourceDirPrefix)) {
            findings += Finding(
                kind = "apk_source_dir_unexpected",
                severity = Severity.MEDIUM,
                subject = apkPath,
                message = "Installed APK lives outside the expected path prefix",
                details = mapOf(
                    "expected_prefix" to baked.expectedSourceDirPrefix,
                    "observed_path" to apkPath,
                ),
            )
        }

        if (baked.expectedInstallerWhitelist.isNotEmpty()) {
            val installer = readInstallerPackageName(context)
            if (installer == null || installer !in baked.expectedInstallerWhitelist) {
                findings += Finding(
                    kind = "installer_not_whitelisted",
                    severity = Severity.MEDIUM,
                    subject = installer,
                    message = "Installer package is not in the baked whitelist",
                    details = mapOf(
                        "whitelist" to baked.expectedInstallerWhitelist.joinToString(","),
                        "observed_installer" to (installer ?: "<null>"),
                    ),
                )
            }
        }

        // Entry-level diff. Filter the runtime view through baked
        // ignore rules so the comparison is apples-to-apples.
        val ignoredEntries = baked.ignoredEntries.toHashSet()
        val ignoredPrefixes = baked.ignoredEntryPrefixes
        val filteredRuntime = HashMap<String, String>(runtimeEntries.size)
        for ((name, hash) in runtimeEntries) {
            if (name in ignoredEntries) continue
            if (ignoredPrefixes.any { name.startsWith(it) }) continue
            filteredRuntime[name] = hash
        }

        for ((name, expectedHash) in baked.entries) {
            val observedHash = filteredRuntime[name]
            when {
                observedHash == null -> findings += Finding(
                    kind = "apk_entry_removed",
                    severity = Severity.HIGH,
                    subject = name,
                    message = "APK entry was present at build time but is missing at runtime",
                    details = mapOf("expected_hash" to expectedHash),
                )
                observedHash != expectedHash -> findings += Finding(
                    kind = "apk_entry_modified",
                    severity = Severity.CRITICAL,
                    subject = name,
                    message = "APK entry exists but its bytes differ from build time",
                    details = mapOf(
                        "expected_hash" to expectedHash,
                        "observed_hash" to observedHash,
                    ),
                )
            }
        }
        for ((name, observedHash) in filteredRuntime) {
            if (name !in baked.entries) {
                findings += Finding(
                    kind = "apk_entry_added",
                    severity = Severity.HIGH,
                    subject = name,
                    message = "APK entry exists at runtime but wasn't present at build time",
                    details = mapOf("observed_hash" to observedHash),
                )
            }
        }

        return ok(id, findings, dur())
    }

    private fun decodeFailureToReport(
        failure: DecodeResult.Failure,
        durationMs: Long,
    ): DetectorReport = when (failure) {
        is DecodeResult.Failure.AssetMissing -> ok(
            id, listOf(
                Finding(
                    kind = "fingerprint_asset_missing",
                    severity = Severity.CRITICAL,
                    subject = Fingerprint.ASSET_PATH,
                    message = "Build-time fingerprint asset is missing from the APK",
                    details = mapOf("decoder_message" to failure.message),
                ),
            ),
            durationMs,
        )
        is DecodeResult.Failure.KeyMissing -> ok(
            id, listOf(
                Finding(
                    kind = "fingerprint_key_missing",
                    severity = Severity.CRITICAL,
                    subject = "io.ssemaj.deviceintelligence.gen.internal.KeyAssembler",
                    message = "Generated key-assembler class is missing — APK was repackaged with codegen stripped",
                    details = mapOf("decoder_message" to failure.message),
                ),
            ),
            durationMs,
        )
        is DecodeResult.Failure.BadMagic -> ok(
            id, listOf(
                Finding(
                    kind = "fingerprint_bad_magic",
                    severity = Severity.CRITICAL,
                    subject = null,
                    message = "Fingerprint blob has wrong magic — likely re-encrypted with a different key",
                    details = mapOf(
                        "observed_magic" to "0x" + failure.observedMagic.toUInt().toString(16),
                    ),
                ),
            ),
            durationMs,
        )
        is DecodeResult.Failure.Corrupt -> ok(
            id, listOf(
                Finding(
                    kind = "fingerprint_corrupt",
                    severity = Severity.HIGH,
                    subject = null,
                    message = "Fingerprint blob is structurally malformed",
                    details = mapOf("decoder_message" to failure.message),
                ),
            ),
            durationMs,
        )
        is DecodeResult.Failure.FormatVersionMismatch -> inconclusive(
            id = id,
            reason = "fingerprint_format_skew",
            message = "fingerprint blob format ${failure.observed} not understood " +
                "by runtime (expected ${failure.expected}); rebuild with matching plugin",
            durationMs = durationMs,
        )
    }

    private fun parseEntryArray(arr: Array<String>): Map<String, String> {
        require(arr.size % 2 == 0) {
            "NativeBridge.apkEntries returned odd-length array (${arr.size})"
        }
        val out = HashMap<String, String>(arr.size / 2)
        var i = 0
        while (i < arr.size) {
            out[arr[i]] = arr[i + 1]
            i += 2
        }
        return out
    }

    @Suppress("DEPRECATION")
    private fun readInstallerPackageName(context: Context): String? {
        val pm: PackageManager = context.packageManager
        val pkg = context.packageName
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkg).installingPackageName
            } else {
                pm.getInstallerPackageName(pkg)
            }
        } catch (t: Throwable) {
            null
        }
    }
}
