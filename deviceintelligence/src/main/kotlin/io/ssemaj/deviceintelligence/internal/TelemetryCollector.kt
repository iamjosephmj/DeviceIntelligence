package io.ssemaj.deviceintelligence.internal

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Resources
import android.hardware.Sensor
import android.hardware.SensorManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.CertValidity
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.DeviceIntelligence
import io.ssemaj.deviceintelligence.InstallSource
import io.ssemaj.deviceintelligence.ReportSummary
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TELEMETRY_SCHEMA_VERSION
import io.ssemaj.deviceintelligence.TelemetryReport

/**
 * The single orchestrator that turns the registered list of
 * [Detector]s into one [TelemetryReport].
 *
 * The list is fixed at construction time. Adding a new detector =
 * one line in [defaultDetectors]. Nothing else in the codebase
 * needs to know it exists — not the public API, not the JSON
 * serializer, not the sample app.
 *
 * Detector ordering in the report mirrors registration order, but
 * the report is otherwise insensitive to ordering — every detector
 * runs and its result lands in [TelemetryReport.detectors] regardless
 * of what others did.
 */
internal object TelemetryCollector {

    private const val TAG = "DeviceIntelligence.Collector"

    /**
     * F10 needs to be addressable separately from the iteration list
     * because [collect] consults its post-evaluation [Fingerprint]
     * cache to populate [AppContext.buildVariant] and
     * [AppContext.libraryPluginVersion]. Keeping the same instance
     * means we don't re-decode.
     */
    private val apkIntegrity = ApkIntegrityDetector()

    private val defaultDetectors: List<Detector> = listOf(
        apkIntegrity,
        EmulatorProbe,
        ClonerDetector,
        KeyAttestationDetector,
        // F15 must run after F14 — it consumes F14's cached
        // attestation result via [KeyAttestationDetector.lastResult].
        BootloaderIntegrityDetector,
        // F16 + F17 are independent of every other detector; they
        // are appended last so any ordering-sensitive future
        // detector slots in before them.
        RuntimeEnvironmentDetector,
        RootIndicatorsDetector,
    )

    fun collect(context: Context): TelemetryReport {
        val started = SystemClock.elapsedRealtime()
        val nativeReady = runCatching { NativeBridge.isReady() }.getOrDefault(false)
        val appCtx = context.applicationContext
        // F10's report is threaded into [DetectorContext.f10Report] so
        // F14 can compute its `app_recognition` against it. Other
        // detectors ignore the field. Update [ctx] in place rather
        // than rebuilding the report list here.
        var ctx = DetectorContext(
            applicationContext = appCtx,
            nativeReady = nativeReady,
        )

        val detectorReports = ArrayList<DetectorReport>(defaultDetectors.size)
        for (det in defaultDetectors) {
            val report = try {
                det.evaluate(ctx)
            } catch (t: Throwable) {
                Log.w(TAG, "detector ${det.id} threw — capturing as ERROR", t)
                errored(det.id, t, 0L)
            }
            detectorReports += report
            if (det === apkIntegrity) {
                ctx = ctx.copy(f10Report = report)
            }
        }

        val device = buildDeviceContext(appCtx)
        val app = buildAppContext(appCtx, nativeReady, detectorReports)
        val summary = computeSummary(detectorReports)

        return TelemetryReport(
            schemaVersion = TELEMETRY_SCHEMA_VERSION,
            libraryVersion = DeviceIntelligence.VERSION,
            collectedAtEpochMs = System.currentTimeMillis(),
            collectionDurationMs = SystemClock.elapsedRealtime() - started,
            device = device,
            app = app,
            detectors = detectorReports,
            summary = summary,
        )
    }

    /**
     * Each observability field is read inside its own
     * `runCatching` so a single failing accessor (sensor service
     * unavailable, missing permission, weird OEM fork) doesn't
     * blank the whole device block. Failures degrade to null,
     * which the JSON encoder emits as `null` for that field only.
     */
    private fun buildDeviceContext(context: Context): DeviceContext {
        val pm = context.packageManager
        val displayMetrics = Resources.getSystem().displayMetrics

        val totalRamMb = runCatching {
            val info = ActivityManager.MemoryInfo()
            (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager)
                .getMemoryInfo(info)
            info.totalMem / 1_048_576L
        }.getOrNull()

        val sensorCount = runCatching {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            sm.getSensorList(Sensor.TYPE_ALL).size
        }.getOrNull()

        val bootCount = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
            } else null
        }.getOrNull()

        val vpnActive = readVpnActive(context)

        return DeviceContext(
            manufacturer = Build.MANUFACTURER ?: "",
            model = Build.MODEL ?: "",
            sdkInt = Build.VERSION.SDK_INT,
            abi = (Build.SUPPORTED_ABIS?.firstOrNull() ?: "").ifEmpty { "unknown" },
            fingerprint = Build.FINGERPRINT ?: "",
            totalRamMb = totalRamMb,
            cpuCores = runCatching { Runtime.getRuntime().availableProcessors() }.getOrNull(),
            screenDensityDpi = runCatching { displayMetrics.densityDpi }.getOrNull(),
            screenResolution = runCatching {
                "${displayMetrics.widthPixels}x${displayMetrics.heightPixels}"
            }.getOrNull(),
            hasFingerprintHw = runCatching {
                pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
            }.getOrNull(),
            hasTelephonyHw = runCatching {
                pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
            }.getOrNull(),
            sensorCount = sensorCount,
            bootCount = bootCount,
            vpnActive = vpnActive,
        )
    }

    /**
     * Iterates active networks and returns true iff any has the VPN
     * transport.
     *
     * Requires `ACCESS_NETWORK_STATE`, which is **opt-in** via the
     * Gradle DSL (`deviceintelligence { enableVpnDetection.set(true) }`).
     * When the consumer hasn't opted in, `getNetworkCapabilities`
     * throws `SecurityException`, the surrounding `runCatching`
     * swallows it, and this method returns `null`. That's the
     * intended graceful degradation: backends can distinguish
     * "no VPN" (`false`) from "permission not granted / lookup
     * broken" (`null`).
     *
     * `getAllNetworks()` is officially deprecated in favour of
     * `NetworkCallback`, but the callback API is event-driven and
     * unfit for a one-shot synchronous probe — we'd have to
     * register a listener, wait for delivery, and unregister, all
     * to learn a fact that's already in the kernel's connection
     * tracking table. The deprecation is suppressed deliberately.
     */
    @Suppress("DEPRECATION")
    private fun readVpnActive(context: Context): Boolean? {
        return runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return@runCatching null
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@runCatching true
            }
            false
        }.getOrNull()
    }

    private fun buildAppContext(
        context: Context,
        nativeReady: Boolean,
        detectorReports: List<DetectorReport>,
    ): AppContext {
        val pkg = context.packageName
        val apkPath = context.applicationInfo?.sourceDir
        val installSource = readInstallSource(context)
        // Backward-compatible scalar form: installingPackage from
        // the rich struct, with the same fallback semantics the
        // previous `readInstaller` helper had.
        val installer = installSource?.installingPackage
        val signers = if (nativeReady && apkPath != null) {
            runCatching { NativeBridge.apkSignerCertHashes(apkPath) }
                .getOrNull()?.toList().orEmpty()
        } else emptyList()

        // Reuse F10's already-decoded fingerprint when available
        // rather than re-decoding from disk a second time.
        val fp = apkIntegrity.lastDecodedFingerprint()

        // F14's raw attestation evidence + advisory verdict ride
        // along on app.attestation, NOT as a Finding inside the F14
        // detector report. See [KeyAttestationDetector] for why.
        // Pass the live F10 report + runtime signers so the wire-
        // shipped verdict matches the one F14's finding-emission
        // path uses — single source of truth across the report.
        val f14Report = detectorReports.firstOrNull { it.id == KeyAttestationDetector.id }
        val f10Report = detectorReports.firstOrNull { it.id == apkIntegrity.id }
        val attestation = f14Report?.let {
            KeyAttestationDetector.toAttestationReport(
                detectorReport = it,
                f10Report = f10Report,
                runtimePackageName = pkg,
                runtimeSignerCertSha256 = signers,
            )
        }

        // PackageInfo lookup is reused for firstInstall / lastUpdate /
        // targetSdk / signer-validity. One PM call is plenty.
        val packageInfo = readPackageInfoForObservability(context)
        val firstInstallEpochMs = packageInfo?.firstInstallTime
        val lastUpdateEpochMs = packageInfo?.lastUpdateTime
        val targetSdkVersion = runCatching {
            context.applicationInfo?.targetSdkVersion
        }.getOrNull()
        val signerCertValidity = readSignerCertValidity(packageInfo)

        return AppContext(
            packageName = pkg,
            apkPath = apkPath,
            installerPackage = installer,
            signerCertSha256 = signers,
            buildVariant = fp?.variantName,
            libraryPluginVersion = fp?.pluginVersion,
            attestation = attestation,
            firstInstallEpochMs = firstInstallEpochMs,
            lastUpdateEpochMs = lastUpdateEpochMs,
            targetSdkVersion = targetSdkVersion,
            installSource = installSource,
            signerCertValidity = signerCertValidity,
        )
    }

    /**
     * Reads the install-attribution triple from `PackageManager`.
     * On API 30+ all three fields can be populated; on 28-29 only
     * [InstallSource.installingPackage] is meaningful (the others
     * are null because the API didn't exist yet).
     *
     * Returns null on lookup failure so the caller can degrade to
     * "unknown" rather than synthesizing a misleading "(none)"
     * value.
     */
    @Suppress("DEPRECATION")
    private fun readInstallSource(context: Context): InstallSource? {
        val pm: PackageManager = context.packageManager
        val pkg = context.packageName
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = pm.getInstallSourceInfo(pkg)
                InstallSource(
                    installingPackage = info.installingPackageName,
                    originatingPackage = info.originatingPackageName,
                    initiatingPackage = info.initiatingPackageName,
                )
            } else {
                InstallSource(
                    installingPackage = pm.getInstallerPackageName(pkg),
                    originatingPackage = null,
                    initiatingPackage = null,
                )
            }
        } catch (t: Throwable) {
            null
        }
    }

    /**
     * Single PackageInfo lookup with GET_SIGNATURES (or its API
     * 28+ replacement, GET_SIGNING_CERTIFICATES) so we get the
     * cert chain without spending a second IPC. Returns null on
     * any failure — every consumer treats null as "field
     * unavailable".
     */
    @Suppress("DEPRECATION")
    private fun readPackageInfoForObservability(context: Context): android.content.pm.PackageInfo? {
        val pm = context.packageManager
        val pkg = context.packageName
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "PackageInfo lookup failed", t)
            null
        }
    }

    /**
     * Walks the cert chain on the [packageInfo], parses each
     * `Signature` into an X.509 cert, and returns its validity
     * window. Returns null on any failure (no signatures, parse
     * error, no chain) — backends treat null as "unavailable".
     */
    @Suppress("DEPRECATION")
    private fun readSignerCertValidity(packageInfo: android.content.pm.PackageInfo?): List<CertValidity>? {
        if (packageInfo == null) return null
        val signatures: Array<android.content.pm.Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // signingInfo can be null on older targets; fall back to legacy field.
            packageInfo.signingInfo?.apkContentsSigners ?: packageInfo.signatures
        } else {
            packageInfo.signatures
        }
        if (signatures.isNullOrEmpty()) return null
        return runCatching {
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            signatures.map { sig ->
                val x509 = cf.generateCertificate(sig.toByteArray().inputStream())
                    as java.security.cert.X509Certificate
                CertValidity(
                    notBeforeEpochMs = x509.notBefore.time,
                    notAfterEpochMs = x509.notAfter.time,
                )
            }
        }.getOrNull()
    }

    private fun computeSummary(reports: List<DetectorReport>): ReportSummary {
        var total = 0
        val bySev = LinkedHashMap<Severity, Int>().apply {
            // Keep iteration order stable for serialisation.
            for (s in Severity.values()) put(s, 0)
        }
        val byKind = LinkedHashMap<String, Int>()
        val withFindings = ArrayList<String>()
        val inconclusive = ArrayList<String>()
        val errored = ArrayList<String>()
        for (r in reports) {
            when (r.status) {
                DetectorStatus.OK -> if (r.findings.isNotEmpty()) {
                    withFindings += r.id
                    for (f in r.findings) {
                        total++
                        bySev[f.severity] = (bySev[f.severity] ?: 0) + 1
                        byKind[f.kind] = (byKind[f.kind] ?: 0) + 1
                    }
                }
                DetectorStatus.INCONCLUSIVE -> inconclusive += r.id
                DetectorStatus.ERROR -> errored += r.id
            }
        }
        return ReportSummary(
            totalFindings = total,
            findingsBySeverity = bySev,
            findingsByKind = byKind,
            detectorsWithFindings = withFindings,
            detectorsInconclusive = inconclusive,
            detectorsErrored = errored,
        )
    }
}
