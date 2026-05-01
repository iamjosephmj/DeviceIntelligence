package io.ssemaj.deviceintelligence.internal

import android.app.ActivityManager
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.res.Resources
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.biometrics.BiometricManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.view.Display
import android.view.WindowManager
import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.CertValidity
import io.ssemaj.deviceintelligence.CollectOptions
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.DeviceIntelligence
import io.ssemaj.deviceintelligence.InstallSource
import io.ssemaj.deviceintelligence.ReportSummary
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TELEMETRY_SCHEMA_VERSION
import io.ssemaj.deviceintelligence.TelemetryReport
import java.security.MessageDigest
import java.util.Locale
import java.util.TimeZone

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
     * `integrity.apk` needs to be addressable separately from the
     * iteration list because [collect] consults its post-evaluation
     * [Fingerprint] cache to populate [AppContext.buildVariant] and
     * [AppContext.libraryPluginVersion]. Keeping the same instance
     * means we don't re-decode.
     */
    private val apkIntegrity = ApkIntegrityDetector()

    private val defaultDetectors: List<Detector> = listOf(
        apkIntegrity,
        EmulatorProbe,
        ClonerDetector,
        KeyAttestationDetector,
        // integrity.bootloader must run after attestation.key — it
        // consumes attestation.key's cached attestation result via
        // [KeyAttestationDetector.lastResult].
        BootloaderIntegrityDetector,
        // runtime.environment + runtime.root + integrity.art are
        // independent of every other detector; they are appended
        // last so any ordering-sensitive future detector slots in
        // before them. integrity.art sits next to runtime.environment
        // by theme (in-process integrity) so they're easy to reason
        // about together.
        RuntimeEnvironmentDetector,
        RootIndicatorsDetector,
        ArtIntegrityDetector,
    )

    fun collect(context: Context): TelemetryReport = collect(context, CollectOptions.DEFAULT)

    fun collect(context: Context, options: CollectOptions): TelemetryReport {
        val started = SystemClock.elapsedRealtime()
        val nativeReady = runCatching { NativeBridge.isReady() }.getOrDefault(false)
        val appCtx = context.applicationContext
        // integrity.apk's report is threaded into
        // [DetectorContext.apkReport] so attestation.key can compute
        // its `app_recognition` against it. Other detectors ignore
        // the field. Update [ctx] in place rather than rebuilding
        // the report list here.
        var ctx = DetectorContext(
            applicationContext = appCtx,
            nativeReady = nativeReady,
        )

        val activeDetectors = filterDetectors(defaultDetectors, options)
        val detectorReports = ArrayList<DetectorReport>(activeDetectors.size)
        // G6 — wrap the detector-execution loop in a sampled
        // stack watchdog. Catches Kotlin/Java method hooks on
        // INTERNAL detector code (which G5 misses because the
        // user never calls those directly). The watchdog runs on
        // a daemon thread with a hard 100-sample cap; its
        // findings are queued onto the same StackGuard.snapshot()
        // surface that RuntimeEnvironmentDetector already polls,
        // so no separate plumbing is required.
        StackWatchdog.watchDuring(Thread.currentThread()) {
            for (det in activeDetectors) {
                val report = try {
                    det.evaluate(ctx)
                } catch (t: Throwable) {
                    Log.w(TAG, "detector ${det.id} threw — capturing as ERROR", t)
                    errored(det.id, t, 0L)
                }
                detectorReports += report
                if (det === apkIntegrity) {
                    ctx = ctx.copy(apkReport = report)
                }
            }
        }

        val device = buildDeviceContext(appCtx)
        val app = buildAppContext(appCtx, nativeReady, detectorReports)
        val summary = computeSummary(detectorReports)

        val report = TelemetryReport(
            schemaVersion = TELEMETRY_SCHEMA_VERSION,
            libraryVersion = DeviceIntelligence.VERSION,
            collectedAtEpochMs = System.currentTimeMillis(),
            collectionDurationMs = SystemClock.elapsedRealtime() - started,
            device = device,
            app = app,
            detectors = detectorReports,
            summary = summary,
        )

        // Ship the freshly-built report to the native analytics drain so
        // the SDK author's backend stores the EXACT same JSON the consumer
        // sees from `DeviceIntelligence.collectJson(...)`. The drain is
        // fire-and-forget on a detached pthread; full ring buffer or
        // disabled-via-manifest cases are silently dropped. Wrapped in
        // runCatching so any future native-side failure can never escape
        // into the consumer's `collect()` call site.
        runCatching {
            NativeBridge.queueTelemetryReport(report.toJson())
        }

        return report
    }

    /**
     * Applies [CollectOptions] to the registered detector list. The
     * iteration order of [defaultDetectors] is preserved — the `only`
     * set acts as a membership filter, not a re-order. This keeps
     * `attestation.key` running before `integrity.bootloader` even
     * when callers list them in the opposite order.
     *
     * `internal` rather than `private` so the JVM unit tests can
     * pin the filter contract without spinning up a real Context.
     */
    internal fun filterDetectors(all: List<Detector>, options: CollectOptions): List<Detector> {
        val only = options.only
        return when {
            only != null -> all.filter { it.id in only }
            options.skip.isNotEmpty() -> all.filter { it.id !in options.skip }
            else -> all
        }
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
            Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
        }.getOrNull()

        val vpnActive = readVpnActive(context)
        val battery = readBattery(context)
        val display = readDisplay(context)
        val locale = readLocale(context)
        val gms = readGoogleEcosystem(context)

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
            strongboxAvailable = runCatching {
                pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            }.getOrNull(),

            // Extended Build identity
            brand = Build.BRAND,
            board = Build.BOARD,
            hardware = Build.HARDWARE,
            product = Build.PRODUCT,
            device = Build.DEVICE,
            bootloaderVersion = Build.BOOTLOADER,
            radioVersion = runCatching { Build.getRadioVersion() }.getOrNull(),
            buildHost = Build.HOST,
            buildUser = Build.USER,
            buildType = Build.TYPE,
            buildTags = Build.TAGS,
            buildTimeEpochMs = runCatching { Build.TIME }.getOrNull()
                ?.takeIf { it > 0 },
            supportedAbisAll = runCatching { Build.SUPPORTED_ABIS?.toList() }.getOrNull(),
            socManufacturer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                runCatching { Build.SOC_MANUFACTURER }.getOrNull()
            } else null,
            socModel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                runCatching { Build.SOC_MODEL }.getOrNull()
            } else null,

            // GPU / EGL hint
            glEsVersion = runCatching {
                (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager)
                    .deviceConfigurationInfo
                    .glEsVersion
            }.getOrNull(),
            eglImplementation = runCatching {
                NativeBridge.systemProperty("ro.hardware.egl")
            }.getOrNull()?.takeIf { it.isNotEmpty() },

            // Locale + timezone
            defaultLocale = locale.defaultLocale,
            systemLocales = locale.systemLocales,
            timezoneId = locale.timezoneId,
            timezoneOffsetMinutes = locale.timezoneOffsetMinutes,
            autoTimeEnabled = runCatching {
                Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME) != 0
            }.getOrNull(),
            autoTimeZoneEnabled = runCatching {
                Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME_ZONE) != 0
            }.getOrNull(),

            // Display extras
            displayRefreshRateHz = display.refreshRateHz,
            displaySupportedRefreshRatesHz = display.supportedRefreshRatesHz,
            displayHdrTypes = display.hdrTypes,

            // Security posture
            deviceSecure = runCatching {
                (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager)
                    .isDeviceSecure
            }.getOrNull(),
            biometricsEnrolled = readBiometricsEnrolled(context),
            adbEnabled = runCatching {
                Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED) != 0
            }.getOrNull(),
            developerOptionsEnabled = runCatching {
                Settings.Global.getInt(
                    context.contentResolver,
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                ) != 0
            }.getOrNull(),

            // Battery + thermal
            batteryPresent = battery.present,
            batteryTechnology = battery.technology,
            batteryHealth = battery.health,
            batteryPlugType = battery.plugType,
            thermalStatus = readThermalStatus(context),

            // Boot derivation
            bootEpochMs = runCatching {
                System.currentTimeMillis() - SystemClock.elapsedRealtime()
            }.getOrNull(),

            // Google ecosystem
            playServicesAvailability = gms.availability,
            playServicesVersionCode = gms.gmsVersionCode,
            playStoreVersionCode = gms.storeVersionCode,
            gmsSignerSha256 = gms.gmsSignerSha256,
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

    // ---- new observability readers ---------------------------------------

    private data class BatterySnapshot(
        val present: Boolean?,
        val technology: String?,
        val health: String?,
        val plugType: String?,
    )

    /**
     * Reads the sticky `ACTION_BATTERY_CHANGED` broadcast — same
     * pattern Android's own battery widgets use. Sticky broadcasts
     * deliver synchronously without a real receiver registration so
     * there's no leak risk.
     */
    private fun readBattery(context: Context): BatterySnapshot {
        val empty = BatterySnapshot(null, null, null, null)
        return runCatching {
            val intent: Intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
                ?: return@runCatching empty
            val present = intent.getBooleanExtra(BatteryManager.EXTRA_PRESENT, false)
                .takeIf { intent.hasExtra(BatteryManager.EXTRA_PRESENT) }
            val tech = intent.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY)
                ?.takeIf { it.isNotEmpty() }
            val healthCode = intent.getIntExtra(BatteryManager.EXTRA_HEALTH, -1)
            val health = when (healthCode) {
                BatteryManager.BATTERY_HEALTH_GOOD -> "good"
                BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
                BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
                BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over_voltage"
                BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
                BatteryManager.BATTERY_HEALTH_COLD -> "cold"
                BatteryManager.BATTERY_HEALTH_UNKNOWN -> "unknown"
                else -> null
            }
            val pluggedCode = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
            val plug = when (pluggedCode) {
                0 -> "none"
                BatteryManager.BATTERY_PLUGGED_AC -> "ac"
                BatteryManager.BATTERY_PLUGGED_USB -> "usb"
                BatteryManager.BATTERY_PLUGGED_WIRELESS -> "wireless"
                BatteryManager.BATTERY_PLUGGED_DOCK -> "dock"
                else -> null
            }
            BatterySnapshot(present, tech, health, plug)
        }.getOrDefault(empty)
    }

    /**
     * `PowerManager.getCurrentThermalStatus()` was introduced in API 29.
     * We're at minSdk 28, so guard the one-version gap.
     */
    private fun readThermalStatus(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return runCatching {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            when (pm.currentThermalStatus) {
                PowerManager.THERMAL_STATUS_NONE -> "none"
                PowerManager.THERMAL_STATUS_LIGHT -> "light"
                PowerManager.THERMAL_STATUS_MODERATE -> "moderate"
                PowerManager.THERMAL_STATUS_SEVERE -> "severe"
                PowerManager.THERMAL_STATUS_CRITICAL -> "critical"
                PowerManager.THERMAL_STATUS_EMERGENCY -> "emergency"
                PowerManager.THERMAL_STATUS_SHUTDOWN -> "shutdown"
                else -> null
            }
        }.getOrNull()
    }

    /**
     * `BiometricManager` requires API 29+. On API 28 we return null
     * (the field is documented as nullable for that reason).
     *
     * On API 30+ the no-arg `canAuthenticate()` is deprecated and
     * unreliable: it returns `BIOMETRIC_ERROR_NO_HARDWARE` on devices
     * that actually have biometrics enrolled. Use the auth-type
     * overload with [BiometricManager.Authenticators.BIOMETRIC_STRONG]
     * (Class 3) — that's the contract every modern fingerprint /
     * Face Unlock-Class-3 sensor signs against.
     */
    private fun readBiometricsEnrolled(context: Context): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return runCatching {
            val bm = context.getSystemService(Context.BIOMETRIC_SERVICE) as BiometricManager
            val status = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                bm.canAuthenticate(
                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
            } else {
                @Suppress("DEPRECATION")
                bm.canAuthenticate()
            }
            status == BiometricManager.BIOMETRIC_SUCCESS
        }.getOrNull()
    }

    private data class DisplaySnapshot(
        val refreshRateHz: Float?,
        val supportedRefreshRatesHz: List<Float>?,
        val hdrTypes: List<String>?,
    )

    /**
     * Pulls the current refresh rate, the panel's full supported set,
     * and the supported HDR-type list from the default display. Each
     * field is captured under its own `runCatching` so a quirky OEM
     * display driver can't blank the whole snapshot.
     */
    @Suppress("DEPRECATION")
    private fun readDisplay(context: Context): DisplaySnapshot {
        val display: Display? = runCatching {
            (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
        }.getOrNull()
        val refresh = runCatching { display?.refreshRate }.getOrNull()
        val supported = runCatching {
            display?.supportedRefreshRates?.toList()?.distinct()?.sorted()
        }.getOrNull()
        val hdr = runCatching {
            display?.hdrCapabilities?.supportedHdrTypes?.map { hdrTypeToWire(it) }
        }.getOrNull()
        return DisplaySnapshot(refresh, supported, hdr)
    }

    private fun hdrTypeToWire(code: Int): String = when (code) {
        Display.HdrCapabilities.HDR_TYPE_DOLBY_VISION -> "DOLBY_VISION"
        Display.HdrCapabilities.HDR_TYPE_HDR10 -> "HDR10"
        Display.HdrCapabilities.HDR_TYPE_HLG -> "HLG"
        Display.HdrCapabilities.HDR_TYPE_HDR10_PLUS -> "HDR10_PLUS"
        else -> "UNKNOWN_$code"
    }

    private data class LocaleSnapshot(
        val defaultLocale: String?,
        val systemLocales: List<String>?,
        val timezoneId: String?,
        val timezoneOffsetMinutes: Int?,
    )

    private fun readLocale(@Suppress("UNUSED_PARAMETER") context: Context): LocaleSnapshot {
        val def = runCatching { Locale.getDefault().toLanguageTag() }.getOrNull()
        val sys = runCatching {
            val locales = Resources.getSystem().configuration.locales
            (0 until locales.size()).map { locales[it].toLanguageTag() }
        }.getOrNull()
        val tz = runCatching { TimeZone.getDefault() }.getOrNull()
        val tzId = runCatching { tz?.id }.getOrNull()
        val tzOffset = runCatching {
            tz?.getOffset(System.currentTimeMillis())?.let { it / 60_000 }
        }.getOrNull()
        return LocaleSnapshot(def, sys, tzId, tzOffset)
    }

    private data class GoogleEcosystemSnapshot(
        val availability: String?,
        val gmsVersionCode: Long?,
        val storeVersionCode: Long?,
        val gmsSignerSha256: String?,
    )

    /**
     * Reads Play Services / Play Store presence + version + GMS signer
     * cert hash directly via [PackageManager]. We don't link against
     * Play Services at all — keeping the SDK dependency-free is the
     * whole point. The "availability" string is computed from the
     * presence + state of `com.google.android.gms`, mimicking the same
     * vocabulary `GoogleApiAvailability` would return so backends that
     * already speak that vocabulary don't need a remap.
     */
    private fun readGoogleEcosystem(context: Context): GoogleEcosystemSnapshot {
        val pm = context.packageManager
        val gmsInfo = runCatching {
            @Suppress("DEPRECATION")
            pm.getPackageInfo("com.google.android.gms", PackageManager.GET_SIGNING_CERTIFICATES)
        }.getOrNull()
        val storeInfo = runCatching {
            @Suppress("DEPRECATION")
            pm.getPackageInfo("com.android.vending", 0)
        }.getOrNull()

        val gmsVersionCode: Long? = gmsInfo?.let { packageVersionLong(it) }
        val storeVersionCode: Long? = storeInfo?.let { packageVersionLong(it) }

        val availability: String = when {
            gmsInfo == null -> "service_missing"
            !gmsInfo.applicationInfo!!.enabled -> "service_disabled"
            else -> "success"
        }

        val signerSha: String? = gmsInfo?.let { sha256OfFirstSigner(it.signingInfo?.apkContentsSigners) }

        return GoogleEcosystemSnapshot(availability, gmsVersionCode, storeVersionCode, signerSha)
    }

    @Suppress("DEPRECATION")
    private fun packageVersionLong(pi: android.content.pm.PackageInfo): Long? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pi.longVersionCode
        else pi.versionCode.toLong()
    }.getOrNull()

    private fun sha256OfFirstSigner(sigs: Array<Signature>?): String? {
        if (sigs.isNullOrEmpty()) return null
        return runCatching {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(sigs[0].toByteArray())
            md.digest().joinToString(separator = "") { b -> "%02x".format(b) }
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

        // Reuse integrity.apk's already-decoded fingerprint when
        // available rather than re-decoding from disk a second time.
        val fp = apkIntegrity.lastDecodedFingerprint()

        // attestation.key's raw attestation evidence + advisory
        // verdict ride along on app.attestation, NOT as a Finding
        // inside the attestation.key detector report. See
        // [KeyAttestationDetector] for why. Pass the live
        // integrity.apk report + runtime signers so the wire-shipped
        // verdict matches the one attestation.key's finding-emission
        // path uses — single source of truth across the report.
        val attestationReport = detectorReports.firstOrNull { it.id == KeyAttestationDetector.id }
        val apkReport = detectorReports.firstOrNull { it.id == apkIntegrity.id }
        val attestation = attestationReport?.let {
            KeyAttestationDetector.toAttestationReport(
                detectorReport = it,
                apkReport = apkReport,
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
     * Single PackageInfo lookup with GET_SIGNING_CERTIFICATES so we
     * get the cert chain without spending a second IPC. Returns null
     * on any failure — every consumer treats null as "field
     * unavailable".
     */
    private fun readPackageInfoForObservability(context: Context): android.content.pm.PackageInfo? {
        val pm = context.packageManager
        val pkg = context.packageName
        return try {
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
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
     *
     * `signingInfo` was added in API 28 and is the floor for this
     * library; the legacy `packageInfo.signatures` is consulted only
     * as a defensive fallback for the rare case where `signingInfo`
     * comes back null on a malformed PackageInfo.
     */
    @Suppress("DEPRECATION")
    private fun readSignerCertValidity(packageInfo: android.content.pm.PackageInfo?): List<CertValidity>? {
        if (packageInfo == null) return null
        val signatures: Array<android.content.pm.Signature>? =
            packageInfo.signingInfo?.apkContentsSigners ?: packageInfo.signatures
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
