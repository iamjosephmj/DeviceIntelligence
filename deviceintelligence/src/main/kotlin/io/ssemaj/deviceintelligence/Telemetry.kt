package io.ssemaj.deviceintelligence

/**
 * The single, structured output of a DeviceIntelligence run.
 *
 * DeviceIntelligence is a *telemetry* layer — it collects facts about the runtime
 * environment of the host app and hands them back as a serialisable
 * report. It does NOT decide whether the app should keep running,
 * shut down, lock the user out, or anything else. That decision
 * belongs to the consumer's backend or in-app policy layer, working
 * off of (typically) [toJson] uploaded from the device.
 *
 * The schema is intentionally flat and stable. Every value below is
 * either a primitive, a string, or a list/map of those — no enums or
 * sealed-class hierarchies leak into the wire format. This means:
 *  - Backends can parse the JSON with any vanilla JSON library.
 *  - Adding a new detector / finding kind is purely additive: it
 *    appears as an extra entry in [detectors] / a new value of
 *    [Finding.kind], without breaking older consumers.
 *  - [schemaVersion] is bumped only on breaking changes.
 *
 * Consumers MUST treat [Finding.kind] and [Finding.severity] as the
 * stable contract; [Finding.details] is opaque diagnostic data whose
 * keys may change without a schema bump.
 */
public data class TelemetryReport(
    /** Wire-format version. Currently 2; bumped only on breaking changes. */
    public val schemaVersion: Int,

    /** DeviceIntelligence library version that produced this report. */
    public val libraryVersion: String,

    /** Wall-clock when collection finished. UTC milliseconds. */
    public val collectedAtEpochMs: Long,

    /** Total wall-clock the [io.ssemaj.deviceintelligence.DeviceIntelligence.collect] call took, including all detectors. */
    public val collectionDurationMs: Long,

    /** Hardware / OS facts about the device the report was collected from. */
    public val device: DeviceContext,

    /** Identity facts about the app instance the report was collected from. */
    public val app: AppContext,

    /** One entry per registered detector, in registration order. */
    public val detectors: List<DetectorReport>,

    /** Pre-computed roll-ups; backends can ignore and recompute themselves. */
    public val summary: ReportSummary,
) {
    /** Renders this report as a deterministic, pretty-printed JSON string. */
    public fun toJson(): String =
        io.ssemaj.deviceintelligence.internal.TelemetryJson.encode(this)
}

/**
 * Stable wire-format version. Incremented only when an existing
 * field's meaning changes or a field is removed. Adding new optional
 * fields, new detector ids, or new [Finding.kind] values is NOT a
 * breaking change.
 *
 * v1 → v2: detector IDs renamed from the sparse `F<n>.<short_name>`
 * scheme to a category-prefixed scheme (`integrity.*`, `attestation.*`,
 * `runtime.*`). Backends that route on `detector.id` or `Finding`
 * payload IDs need to be updated; the rest of the wire format is
 * unchanged. See [DetectorReport.id] for the new ID convention.
 */
public const val TELEMETRY_SCHEMA_VERSION: Int = 2

/**
 * Per-call configuration for `DeviceIntelligence.collect` and
 * `DeviceIntelligence.observe`. Default-constructed instance runs
 * every registered detector — i.e. the same behaviour as not
 * passing options at all.
 *
 * Filtering by detector id lets a consumer:
 *
 *  - Skip an expensive detector on a hot path (e.g. drop
 *    `integrity.apk` when polling for `integrity.art` in a tight
 *    `observe()` loop).
 *  - Skip a detector that's intentionally disabled by deployment
 *    shape (e.g. `integrity.apk` is meaningless in
 *    library-only-mode where the Gradle plugin isn't applied).
 *  - Constrain `observe()` to the small set of detectors that
 *    actually re-evaluate per-call (effectively just `integrity.art`
 *    today; everything else memoizes for the process lifetime).
 *
 * Filtering only changes which entries appear in
 * [TelemetryReport.detectors]. Skipped detectors do not appear at
 * all (no INCONCLUSIVE / placeholder entry) — backends that key on
 * "every detector ran" should pin their expectations off the same
 * `CollectOptions` they passed in.
 *
 * `device.*` and `app.*` blocks are *always* populated regardless
 * of the filter; they're the cheap observability surface and the
 * hard dependencies between them and detector caches (e.g.
 * `app.attestation` reads `attestation.key`'s last result if
 * available) make per-block filtering not worth the API surface.
 */
public data class CollectOptions(
    /**
     * Detector ids to skip. Ignored when [only] is non-null.
     *
     * Example: `CollectOptions(skip = setOf("integrity.apk"))` for
     * library-only-mode consumers who never apply the Gradle plugin.
     */
    public val skip: Set<String> = emptySet(),

    /**
     * If non-null, only detectors whose id is in this set run.
     * Takes precedence over [skip].
     *
     * Example: `CollectOptions(only = setOf("integrity.art"))` for a
     * hot `observe()` loop watching for runtime ART tampering.
     *
     * Empty set is allowed and means "no detectors run" — the
     * report is still produced with `device.*` / `app.*` populated
     * and an empty `detectors[]` list.
     */
    public val only: Set<String>? = null,
) {
    public companion object {
        /** Convenience accessor for the default — every detector runs. */
        @JvmField
        public val DEFAULT: CollectOptions = CollectOptions()
    }
}

/**
 * Hardware / OS context. Mirrors [android.os.Build] but trimmed to
 * fields that are stable, useful for cohorting, and not PII.
 *
 * The fields below the [fingerprint] field are observability data
 * (no detector consumes them); they're shipped purely so backends
 * can cohort reports and run cheap emulator / fraud-ring heuristics
 * server-side. Every one of them is nullable: any single read can
 * fail (permission denied, missing system service, API-level guard)
 * without affecting the rest of the report.
 */
public data class DeviceContext(
    public val manufacturer: String,
    public val model: String,
    public val sdkInt: Int,
    public val abi: String,
    /**
     * `Build.FINGERPRINT`. Useful for grouping reports by ROM build
     * (a rooted ROM often has a hand-edited fingerprint).
     */
    public val fingerprint: String,

    // ---- observability fields (cohorting / fraud heuristics) ----

    /** Total RAM in mebibytes, from `ActivityManager.MemoryInfo.totalMem`. */
    public val totalRamMb: Long? = null,
    /** `Runtime.getRuntime().availableProcessors()`. */
    public val cpuCores: Int? = null,
    /** `Resources.system.displayMetrics.densityDpi`. */
    public val screenDensityDpi: Int? = null,
    /** Display resolution as `"WIDTHxHEIGHT"` (e.g. `"1080x2400"`). */
    public val screenResolution: String? = null,
    /** `PackageManager.FEATURE_FINGERPRINT`. */
    public val hasFingerprintHw: Boolean? = null,
    /** `PackageManager.FEATURE_TELEPHONY`. */
    public val hasTelephonyHw: Boolean? = null,
    /** `SensorManager.getSensorList(Sensor.TYPE_ALL).size`. */
    public val sensorCount: Int? = null,
    /** `Settings.Global.BOOT_COUNT` (API 24+). */
    public val bootCount: Int? = null,
    /**
     * True iff the device currently has an active VPN transport.
     * Read via `ConnectivityManager`; requires
     * `ACCESS_NETWORK_STATE`. Null if the permission isn't granted
     * or the lookup fails.
     */
    public val vpnActive: Boolean? = null,
    /**
     * True iff the device advertises
     * [PackageManager.FEATURE_STRONGBOX_KEYSTORE] — i.e. it has a
     * discrete StrongBox / Titan-M-class secure element capable of
     * backing keystore keys. Pure capability flag; independent of
     * whether `attestation.key`'s attestation actually used StrongBox
     * (that's [AttestationReport.attestationSecurityLevel]).
     *
     * Useful for cohorting: a backend can compare the `MEETS_STRONG_INTEGRITY`
     * rate across `strongbox_available = true` vs `false` cohorts to
     * detect StrongBox bypasses on devices that *should* attest at
     * STRONG_BOX. `integrity.bootloader` also consumes this flag to
     * broaden its `bootloader_strongbox_unavailable` trigger beyond
     * the hardcoded Pixel-3+ denylist.
     *
     * Null if the lookup failed (rare).
     */
    public val strongboxAvailable: Boolean? = null,

    // ---- extended Build.* identity (cohorting / emulator detection) ----

    /** `Build.BRAND` — often differs from [manufacturer] (Xiaomi vs Redmi vs Poco). */
    public val brand: String? = null,
    /** `Build.BOARD` — board name (`oriole`, `caiman`). */
    public val board: String? = null,
    /** `Build.HARDWARE` — SoC platform (`tensor`, `qcom`, `mt6789`, `goldfish`/`ranchu` on emulators). */
    public val hardware: String? = null,
    /** `Build.PRODUCT` — product line. */
    public val product: String? = null,
    /** `Build.DEVICE` — device codename (`caiman` for Pixel 9 Pro). Stable across [model] rebrands. */
    public val device: String? = null,
    /** `Build.BOOTLOADER` — bootloader version string. Custom ROMs leak modified strings here. */
    public val bootloaderVersion: String? = null,
    /** `Build.getRadioVersion()` — baseband version. Emulators report `unknown`. */
    public val radioVersion: String? = null,
    /** `Build.HOST` — build-machine hostname. OEMs use corporate CI hosts; custom ROMs leak weird hostnames. */
    public val buildHost: String? = null,
    /** `Build.USER` — build-machine user account. Real OEMs use `android-build`-style accounts. */
    public val buildUser: String? = null,
    /** `Build.TYPE` — `user` / `userdebug` / `eng`. Anything other than `user` on a "production" device is suspicious. */
    public val buildType: String? = null,
    /** `Build.TAGS` — comma-separated build tags. `runtime.root` trips on `test-keys`; this field surfaces the value unconditionally for cohorting. */
    public val buildTags: String? = null,
    /** `Build.TIME` — when the system image was built. Wall-clock ms. */
    public val buildTimeEpochMs: Long? = null,
    /** `Build.SUPPORTED_ABIS` (full list). [abi] is the first entry. Disambiguates 64-bit-only devices and 32-bit emulator forks. */
    public val supportedAbisAll: List<String>? = null,
    /** `Build.SOC_MANUFACTURER` (API 31+). Actual silicon vendor (`Qualcomm`, `Google`). Null on API 28-30. */
    public val socManufacturer: String? = null,
    /** `Build.SOC_MODEL` (API 31+). Actual silicon model (`SM8550-AC`, `Tensor G3`). Null on API 28-30. */
    public val socModel: String? = null,

    // ---- GPU / EGL hint ----

    /** OpenGL ES version string (e.g. `"3.2"`). From `ActivityManager.getDeviceConfigurationInfo().getGlEsVersion()`. */
    public val glEsVersion: String? = null,
    /** EGL implementation library name from `getprop ro.hardware.egl` (`mali`, `adreno`, `swiftshader` on emulators). */
    public val eglImplementation: String? = null,

    // ---- locale + timezone ----

    /** `Locale.getDefault().toLanguageTag()` — e.g. `"en-US"`. */
    public val defaultLocale: String? = null,
    /** All locales the system advertises (`Resources.system.configuration.locales`). Multi-language phones tell you a lot. */
    public val systemLocales: List<String>? = null,
    /** `TimeZone.getDefault().id` — e.g. `"Europe/London"`. */
    public val timezoneId: String? = null,
    /** Current UTC offset in minutes. Backends correlate against IP geolocation; mismatch is a strong VPN-fraud signal. */
    public val timezoneOffsetMinutes: Int? = null,
    /** `Settings.Global.AUTO_TIME` — manual clock on a "production" device usually means a fraud rig. */
    public val autoTimeEnabled: Boolean? = null,
    /** `Settings.Global.AUTO_TIME_ZONE` — companion to [autoTimeEnabled]. */
    public val autoTimeZoneEnabled: Boolean? = null,

    // ---- display extras ----

    /** Current refresh rate (`Display.getRefreshRate()`). Modern flagships report 90/120/144; emulators stuck at 60. */
    public val displayRefreshRateHz: Float? = null,
    /** All refresh rates the panel supports. Emulators: `[60.0]`; modern phones: `[60, 90, 120]`. */
    public val displaySupportedRefreshRatesHz: List<Float>? = null,
    /** Names of supported HDR types (`"HDR10"`, `"HDR10_PLUS"`, `"DOLBY_VISION"`, `"HLG"`). Empty list when SDR-only. */
    public val displayHdrTypes: List<String>? = null,

    // ---- security posture ----

    /** `KeyguardManager.isDeviceSecure` — true iff a PIN/pattern/password is set. Bot farms rarely bother. */
    public val deviceSecure: Boolean? = null,
    /**
     * `BiometricManager.canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS`.
     *
     * Requires the `USE_BIOMETRIC` permission, which is **opt-in**
     * via the Gradle DSL
     * (`deviceintelligence { enableBiometricsDetection.set(true) }`).
     * Without the opt-in, `canAuthenticate` throws SecurityException
     * and this field reports `null`.
     *
     * Null on API 28 (BiometricManager is API 29+) regardless of opt-in.
     */
    public val biometricsEnrolled: Boolean? = null,
    /** `Settings.Global.ADB_ENABLED`. Bot farms / dev rigs often leave this on. */
    public val adbEnabled: Boolean? = null,
    /** `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`. Companion to [adbEnabled]. */
    public val developerOptionsEnabled: Boolean? = null,

    // ---- battery + thermal ----

    /** From the sticky `ACTION_BATTERY_CHANGED` broadcast. Emulators sometimes report no battery. */
    public val batteryPresent: Boolean? = null,
    /** `EXTRA_TECHNOLOGY` — `"Li-ion"` / `"Li-poly"` on real devices, `"Unknown"` on emulators. */
    public val batteryTechnology: String? = null,
    /** Stable string form of `EXTRA_HEALTH`: `"good"` / `"overheat"` / `"dead"` / `"over_voltage"` / `"failure"` / `"cold"` / `"unknown"`. */
    public val batteryHealth: String? = null,
    /** Stable string form of `EXTRA_PLUGGED`: `"none"` / `"ac"` / `"usb"` / `"wireless"` / `"dock"`. Click farms are always plugged in. */
    public val batteryPlugType: String? = null,
    /**
     * `PowerManager.getCurrentThermalStatus()` (API 29+) as a stable string:
     * `"none"` / `"light"` / `"moderate"` / `"severe"` / `"critical"` /
     * `"emergency"` / `"shutdown"`. Null on API 28.
     */
    public val thermalStatus: String? = null,

    // ---- boot derivation ----

    /**
     * Wall-clock when the device booted, derived as
     * `System.currentTimeMillis() - SystemClock.elapsedRealtime()`. Cheap
     * derived field; backends use it to detect clock-jump fraud (boot
     * epoch in the future) and replay attacks (epoch suspiciously old).
     */
    public val bootEpochMs: Long? = null,

    // ---- Google ecosystem ----

    /**
     * `GoogleApiAvailability.isGooglePlayServicesAvailable` as a stable string:
     * `"success"` / `"service_missing"` / `"service_version_update_required"` /
     * `"service_disabled"` / `"service_invalid"` / `"unknown"`. Confirms the
     * device is in the Google ecosystem (or not — MicroG, Huawei, etc.).
     */
    public val playServicesAvailability: String? = null,
    /** GMS package version code from `PackageManager.getPackageInfo("com.google.android.gms")`. Null when GMS isn't installed. */
    public val playServicesVersionCode: Long? = null,
    /** Play Store package version code from `PackageManager.getPackageInfo("com.android.vending")`. Null when not installed. */
    public val playStoreVersionCode: Long? = null,
    /**
     * SHA-256 hex of the GMS signing certificate. Real Google-signed GMS
     * has a stable known value; MicroG / re-signed GMS reports a different
     * hash. Null when GMS isn't installed or signers couldn't be read.
     */
    public val gmsSignerSha256: String? = null,
)

/**
 * App-instance context. These are facts the consumer knows about
 * itself, but having them on the report side simplifies backend
 * grouping and removes an entire class of mismatched-metadata bugs.
 */
public data class AppContext(
    public val packageName: String,
    public val apkPath: String?,
    /**
     * Single-string installer name from `PackageManager.getInstallerPackageName`
     * (or, on API 30+, `getInstallSourceInfo().installingPackageName`).
     * Kept for backward compatibility with reports that pre-date the
     * richer [installSource] block, which carries the same value plus
     * the originating / initiating package fields.
     */
    public val installerPackage: String?,
    /** SHA-256 hex of every signer cert observed at runtime, in the order `integrity.apk` returns them. */
    public val signerCertSha256: List<String>,
    /** AGP build variant the running APK was compiled from (e.g. "debug"). May be null if the `integrity.apk` fingerprint hasn't been decoded. */
    public val buildVariant: String?,
    /** deviceintelligence-gradle plugin version that produced the baked fingerprint. May be null if the fingerprint hasn't been decoded. */
    public val libraryPluginVersion: String?,
    /**
     * Hardware key-attestation evidence captured by `attestation.key`,
     * plus the locally derived advisory verdict.
     *
     * Lives here rather than as a [Finding] inside the `attestation.key`
     * detector report because it is *always-shipped raw evidence* —
     * backends need it on every report to perform authoritative
     * server-side re-verification of the cert chain (against Google's
     * root + revocation list), which is the only verdict the library
     * considers authoritative. `attestation.key`'s detector findings
     * are reserved for advisory anomaly signals
     * (`tee_integrity_verdict` only surfaces when the local verdict
     * is degraded).
     *
     * Non-null but with [AttestationReport.unavailableReason]
     * populated when a specific keygen attempt failed (e.g. no
     * KeyMint implementation in a stripped AOSP build, or the
     * keystore was uninitialised). The library's minSdk is 28, so
     * the "device doesn't support attestation at all" case is no
     * longer reachable at runtime.
     */
    public val attestation: AttestationReport? = null,

    // ---- observability fields (cohorting / fraud heuristics) ----

    /** Wall-clock first install time, from `PackageInfo.firstInstallTime`. */
    public val firstInstallEpochMs: Long? = null,
    /** Wall-clock last update time, from `PackageInfo.lastUpdateTime`. */
    public val lastUpdateEpochMs: Long? = null,
    /** `applicationInfo.targetSdkVersion`. */
    public val targetSdkVersion: Int? = null,
    /**
     * Richer install attribution. Distinguishes who triggered the
     * install vs which package the install originated from (e.g.
     * Play Store / sideload / third-party store). Null on devices
     * where the lookup failed. Originating / initiating fields
     * require API 30+; on the library's minSdk floor (API 28-29)
     * only [InstallSource.installingPackage] is populated.
     */
    public val installSource: InstallSource? = null,
    /**
     * Per-signer cert validity periods, in the same order as
     * [signerCertSha256]. Useful for cert-expiry monitoring and
     * spotting old re-signed APKs. Null if the validity periods
     * couldn't be extracted (e.g. native bridge unavailable).
     */
    public val signerCertValidity: List<CertValidity>? = null,
)

/**
 * Install attribution for the running APK. Wraps the three
 * package-name fields exposed by `PackageManager.getInstallSourceInfo`
 * (API 30+) plus the older `getInstallerPackageName` value as a
 * fallback for API 28-29 (the library's minSdk floor).
 *
 *  - [installingPackage]: the package responsible for the install
 *    that produced the current APK. On a Play Store install this is
 *    typically `com.android.vending`. Sideloaded APKs may report
 *    `com.android.shell`, `com.android.packageinstaller`, or null.
 *  - [originatingPackage]: the package that *originally* delivered
 *    the APK (chain-of-custody hint when an installer wraps another
 *    installer). Null on API <30 and frequently null even on 30+.
 *  - [initiatingPackage]: the package that initiated the install
 *    request. Distinguishes "Play Store served the APK" (initiating
 *    + installing both Play) from "Browser downloaded the APK and
 *    handed it to the package installer" (initiating = browser,
 *    installing = packageinstaller). Null on API <30.
 */
public data class InstallSource(
    public val installingPackage: String?,
    public val originatingPackage: String?,
    public val initiatingPackage: String?,
)

/**
 * Validity period of a single signer certificate. Both bounds are
 * UTC milliseconds since epoch. Useful for backends that want to
 * monitor cert expiry or flag freshly re-signed APKs.
 */
public data class CertValidity(
    public val notBeforeEpochMs: Long,
    public val notAfterEpochMs: Long,
)

/**
 * Hardware key-attestation evidence shipped on every report, plus
 * the locally derived advisory verdict. Always reflects a single
 * `attestation.key` keygen pass that was cached at process start.
 *
 * **Authority caveat.** None of the parsed fields below are
 * authoritative on their own — the on-device library does not walk
 * the cert chain to Google's pinned attestation root or check the
 * revocation list. Backends MUST re-verify [chainB64] server-side.
 * The `verdict_*` fields are advisory-only (used for in-app UX
 * gating, not for security decisions).
 *
 * All parsed fields are nullable: a malformed or unparseable
 * `KeyDescription` extension yields a non-null [AttestationReport]
 * with [chainB64] populated and the parsed fields null, so the
 * backend can still do the work from the raw chain bytes.
 *
 * **JSON wire shape vs typed shape.** [TelemetryReport.toJson] omits
 * the heavier diagnostic fields ([chainB64], [attestationChallengeB64],
 * [attestedApplicationIdSha256], [verifiedBootKeySha256],
 * [keymasterVersion], [osVersion], [vendorPatchLevel],
 * [bootPatchLevel]) to keep the wire format compact and human-
 * readable — the JSON ships a [chainSha256] for backend correlation
 * instead. Backends that need to do authoritative re-verification of
 * the chain bytes read this typed object directly (see
 * `AppContext.attestation`) rather than parsing them out of JSON.
 */
public data class AttestationReport(
    /**
     * Pipe-separated base64 of every cert in the chain (leaf first,
     * root last). The single piece of authoritative evidence on this
     * report; everything else is parsed convenience.
     *
     * Null when [unavailableReason] is set. NOT shipped in JSON
     * output; backend uploaders read this field directly off the
     * typed report.
     */
    public val chainB64: String?,
    /**
     * Lowercase hex SHA-256 of the raw concatenated chain bytes
     * (`chainB64.toByteArray(US-ASCII)`). Cheap correlation /
     * dedup key for backends that don't need the bytes themselves.
     * Null when [unavailableReason] is set.
     */
    public val chainSha256: String?,
    /** Number of certs in the chain. Zero when [chainB64] is null. */
    public val chainLength: Int,

    // ---- parsed KeyDescription extension fields ----

    /** Hardware tier of the attestation cert itself: `"StrongBox"`, `"TrustedEnvironment"`, or `"Software"`. */
    public val attestationSecurityLevel: String?,
    /** Hardware tier of the attested key: same vocabulary as [attestationSecurityLevel]. */
    public val keymasterSecurityLevel: String?,
    /**
     * Convenience boolean derived from the two security-level fields
     * above: `true` iff EITHER [attestationSecurityLevel] OR
     * [keymasterSecurityLevel] is `"Software"`. A software-backed
     * KeyMint implementation means there is no real TEE backing the
     * keys at all — the device is either a stripped AOSP build, an
     * emulator, or a soft-keymint shim and the attestation chain
     * carries effectively zero hardware guarantees.
     *
     * Null when neither security level was readable (e.g. the
     * attestation extension failed to parse). Non-software backings
     * (TrustedEnvironment, StrongBox) report `false`.
     */
    public val softwareBacked: Boolean?,
    /** KeyMaster / KeyMint version (e.g. `41`, `100`, `200`, `300`). Diagnostic; not in default JSON. */
    public val keymasterVersion: Int?,
    /** Base64 of the per-keygen nonce the TEE echoed into the leaf. Diagnostic; not in default JSON. */
    public val attestationChallengeB64: String?,
    /** `"Verified"`, `"SelfSigned"`, `"Unverified"`, or `"Failed"`. */
    public val verifiedBootState: String?,
    /** True iff the bootloader is locked, per the TEE. */
    public val deviceLocked: Boolean?,
    /** SHA-256 hex of the Verified Boot signing key. Stable per OEM/ROM. Diagnostic; not in default JSON. */
    public val verifiedBootKeySha256: String?,
    /** Diagnostic; not in default JSON (correlatable from `device.fingerprint`). */
    public val osVersion: Int?,
    /** Format `YYYYMM` on KM4, `YYYYMMDD` on KM4.1+. Useful for patch-age policy. */
    public val osPatchLevel: Int?,
    /** Diagnostic; not in default JSON. */
    public val vendorPatchLevel: Int?,
    /** Diagnostic; not in default JSON. */
    public val bootPatchLevel: Int?,
    public val attestedPackageName: String?,
    /** SHA-256 hex of the raw `attestation_application_id` blob. Diagnostic; not in default JSON. */
    public val attestedApplicationIdSha256: String?,
    /** SHA-256 hex of every attested signer cert. Compare against [AppContext.signerCertSha256]. */
    public val attestedSignerCertSha256: List<String>,

    // ---- locally derived advisory verdict ----

    /**
     * Comma-separated subset of the Play-Integrity-API spelling:
     * `"MEETS_BASIC_INTEGRITY"`, `"MEETS_DEVICE_INTEGRITY"`,
     * `"MEETS_STRONG_INTEGRITY"`. Wire-compatible with Play Integrity
     * consumers.
     */
    public val verdictDeviceRecognition: String?,
    /** `"RECOGNIZED"` / `"UNRECOGNIZED_VERSION"` / `"UNEVALUATED"`. */
    public val verdictAppRecognition: String?,
    /** Stable short-code for the first failed requirement (e.g. `"bootloader_unlocked"`, `"patch_too_old"`). Null on full pass. */
    public val verdictReason: String?,
    /** Always `false` on-device. Backends decide authority after server-side chain verification. */
    public val verdictAuthoritative: Boolean,

    // ---- failure modes ----

    /**
     * Stable code surfaced when the `attestation.key` keygen couldn't run:
     * `"attestation_not_supported"`, `"keystore_error"`,
     * `"keystore_unavailable"`, `"missing_package_name"`. Null on
     * success.
     *
     * `"api_too_low"` was historically emitted on devices below
     * API 28 and is preserved in the documented value set for
     * wire-format stability, but the library's current minSdk is
     * 28 so the codepath is no longer reachable.
     */
    public val unavailableReason: String?,
)

/**
 * Output of a single [Detector]'s run. Always present in
 * [TelemetryReport.detectors] for every registered detector, even
 * if it found nothing — absence and "found nothing" are different
 * facts and we report both.
 */
public data class DetectorReport(
    /**
     * Stable detector id following the `<category>.<scope>`
     * convention, e.g. `"integrity.apk"`. Categories are
     * `integrity`, `attestation`, `runtime`. Unique within a
     * [TelemetryReport].
     */
    public val id: String,

    /** [DetectorStatus.OK] is the only status that allows [findings] to be trusted. */
    public val status: DetectorStatus,

    /** Wall-clock the detector took. */
    public val durationMs: Long,

    /** Findings produced by this detector. Empty when [status] != OK or when the detector ran cleanly. */
    public val findings: List<Finding>,

    /** Set when [status] == [DetectorStatus.INCONCLUSIVE]; otherwise null. Stable identifier suitable for backend grouping. */
    public val inconclusiveReason: String? = null,

    /** Set when [status] == [DetectorStatus.ERROR]; otherwise null. Free-form diagnostic. */
    public val errorMessage: String? = null,
)

/**
 * One concrete piece of evidence produced by a detector.
 *
 * Stable contract for backends:
 *  - [kind]: stable identifier for grouping and alerting.
 *  - [severity]: DeviceIntelligence's *suggested* severity. Backends MAY override
 *    per their own policy; severity is never a verdict.
 *  - [subject]: free-form identifier of what was inspected (a package
 *    name, an APK entry, a region label). Useful for grouping and
 *    showing in UIs.
 *  - [message]: human-readable one-liner, deterministic per
 *    (`kind`, `details`). Suitable as the headline in an alert.
 *
 * Opaque (unstable) contract:
 *  - [details]: a string-keyed bag of diagnostic information whose
 *    keys may change without a schema bump. Useful for forensics,
 *    NOT suitable as a programmatic contract surface.
 */
public data class Finding(
    public val kind: String,
    public val severity: Severity,
    public val subject: String?,
    public val message: String,
    public val details: Map<String, String>,
)

/**
 * Suggested severity tier for a [Finding]. Backends MAY treat this
 * as policy input but DeviceIntelligence itself never acts on severity — that's
 * not DeviceIntelligence's job.
 */
public enum class Severity {
    /** Informational; expected on most devices (e.g. running on a beta-channel ROM). */
    LOW,

    /** Possibly suspicious; could be benign on some devices (e.g. installer is sideload). */
    MEDIUM,

    /** Strong tampering signal that warrants attention (e.g. running on an emulator). */
    HIGH,

    /** Direct evidence of an active attack channel (e.g. running inside an app cloner, foreign code in process). */
    CRITICAL,
}

/**
 * Outcome status for a [DetectorReport].
 */
public enum class DetectorStatus {
    /** Detector ran cleanly; [DetectorReport.findings] reflects what it found (possibly empty). */
    OK,

    /** Detector tried but couldn't reach a conclusion (missing native lib, unreadable file, format skew). [DetectorReport.inconclusiveReason] explains. */
    INCONCLUSIVE,

    /** Detector threw an unexpected exception. [DetectorReport.errorMessage] has details. */
    ERROR,
}

/**
 * Pre-computed roll-ups derived from [TelemetryReport.detectors].
 * Provided as a convenience so a backend doesn't have to recompute
 * every common stat. Always consistent with the underlying detector
 * reports.
 */
public data class ReportSummary(
    public val totalFindings: Int,
    public val findingsBySeverity: Map<Severity, Int>,
    public val findingsByKind: Map<String, Int>,
    public val detectorsWithFindings: List<String>,
    public val detectorsInconclusive: List<String>,
    public val detectorsErrored: List<String>,
)
