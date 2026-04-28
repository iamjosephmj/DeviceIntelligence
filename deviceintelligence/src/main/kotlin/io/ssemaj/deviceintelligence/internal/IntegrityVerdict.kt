package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.Severity
import java.util.Calendar
import java.util.TimeZone

/**
 * Play-Integrity-shaped verdict derived locally from a parsed
 * [ParsedKeyDescription] plus the F10 [DetectorReport] from the
 * same `collect()` call.
 *
 * The verdict is **advisory** — the on-device library does not
 * walk the cert chain to Google's attestation root, does not check
 * the revocation list, and does not recompute the signed bytes.
 * An attacker who controls userland could patch this verdict before
 * it reaches the report. Backends that need an authoritative
 * verdict MUST re-verify the cert chain shipped at
 * `app.attestation.chain_b64` server-side.
 *
 * The wire spelling of [DeviceTier] and [AppRecognition] mirrors
 * Google Play Integrity API field values verbatim — backends
 * already wired up to Play Integrity can consume this verdict
 * with no remapping.
 */
internal data class IntegrityVerdict(
    /** Subset of the three device-integrity tiers actually met. */
    val deviceRecognition: Set<DeviceTier>,
    /** Whether the running APK matches what we baked + what the TEE attests for. */
    val appRecognition: AppRecognition,
    /** Suggested severity for the surrounding [io.ssemaj.deviceintelligence.Finding]. */
    val severity: Severity,
    /** Stable short code identifying the *first* missing requirement, or null on full pass. */
    val reason: String?,
)

/**
 * Tiered device-integrity verdict, modelled on
 * `Play Integrity API: deviceIntegrity.deviceRecognitionVerdict`.
 *
 * Tiers are *additive* — meeting STRONG implies meeting DEVICE
 * implies meeting BASIC. The wire spelling matches Play Integrity's
 * field values so consumers don't need a remapping table.
 */
internal enum class DeviceTier(val wire: String) {
    MEETS_BASIC_INTEGRITY("MEETS_BASIC_INTEGRITY"),
    MEETS_DEVICE_INTEGRITY("MEETS_DEVICE_INTEGRITY"),
    MEETS_STRONG_INTEGRITY("MEETS_STRONG_INTEGRITY"),
}

/**
 * App-side verdict, modelled on
 * `Play Integrity API: appIntegrity.appRecognitionVerdict`. Wire
 * spellings differ slightly from Google's (no `PLAY_` prefix because
 * we don't depend on Play) but the semantics map 1:1.
 */
internal enum class AppRecognition(val wire: String) {
    /** F10 clean AND attested package + signer match runtime. */
    RECOGNIZED("RECOGNIZED"),
    /** F10 found a mismatch, OR attested identity disagrees with runtime. */
    UNRECOGNIZED_VERSION("UNRECOGNIZED_VERSION"),
    /** F10 didn't run cleanly OR no attested signer digests to compare. */
    UNEVALUATED("UNEVALUATED"),
}

/**
 * Maximum age (in days) the OS patch level may be while still
 * qualifying the device for `MEETS_STRONG_INTEGRITY`. Mirrors
 * Google's own threshold for the strong tier within an order of
 * magnitude — they document "within the past year" without
 * pinning an exact value.
 */
internal const val MAX_PATCH_AGE_DAYS: Long = 365L

/**
 * Pure deriver. No I/O, no Android types, no static state — kept
 * as a top-level function on purpose so the unit test for verdict
 * derivation doesn't have to bring up the Android framework.
 *
 * @param parsed              parsed KeyDescription extension; pass
 *                            null only if the parser couldn't decode
 *                            anything (the deriver will return
 *                            UNEVALUATED + CRITICAL in that case).
 * @param f10Report           F10's report from the same `collect()`
 *                            call. Null means F10 hasn't run yet
 *                            (verdict downgrades app_recognition
 *                            to UNEVALUATED).
 * @param runtimePackageName  consumer's runtime `Context.packageName`.
 * @param runtimeSignerCertSha256  consumer's runtime signer cert
 *                            SHA-256 hashes (lowercase hex; matches
 *                            the format the rest of the library uses).
 * @param nowEpochMs          wall-clock for patch-age computation.
 *                            Parameterised so tests can pin time.
 */
internal fun deriveIntegrityVerdict(
    parsed: ParsedKeyDescription?,
    f10Report: DetectorReport?,
    runtimePackageName: String,
    runtimeSignerCertSha256: List<String>,
    nowEpochMs: Long,
): IntegrityVerdict {
    if (parsed == null) {
        return IntegrityVerdict(
            deviceRecognition = emptySet(),
            appRecognition = AppRecognition.UNEVALUATED,
            severity = Severity.CRITICAL,
            reason = "key_description_unparseable",
        )
    }

    val tiers = LinkedHashSet<DeviceTier>(3)
    var firstFailure: String? = null

    val isHardware = parsed.attestationSecurityLevel == SecurityLevel.TRUSTED_ENVIRONMENT ||
        parsed.attestationSecurityLevel == SecurityLevel.STRONG_BOX
    if (isHardware) {
        tiers += DeviceTier.MEETS_BASIC_INTEGRITY
    } else if (firstFailure == null) {
        firstFailure = "software_attestation"
    }

    val isGenuineOs = isHardware &&
        (parsed.verifiedBootState == VerifiedBootState.VERIFIED ||
            parsed.verifiedBootState == VerifiedBootState.SELF_SIGNED)
    if (isGenuineOs) {
        tiers += DeviceTier.MEETS_DEVICE_INTEGRITY
    } else if (isHardware && firstFailure == null) {
        firstFailure = when (parsed.verifiedBootState) {
            VerifiedBootState.UNVERIFIED, null -> "boot_unverified"
            VerifiedBootState.FAILED -> "boot_failed"
            else -> "boot_unrecognized"
        }
    }

    val isStrong = isGenuineOs &&
        parsed.verifiedBootState == VerifiedBootState.VERIFIED &&
        parsed.deviceLocked == true &&
        isPatchRecent(parsed.osPatchLevel, nowEpochMs)
    if (isStrong) {
        tiers += DeviceTier.MEETS_STRONG_INTEGRITY
    } else if (isGenuineOs && firstFailure == null) {
        firstFailure = when {
            parsed.deviceLocked != true -> "bootloader_unlocked"
            parsed.verifiedBootState != VerifiedBootState.VERIFIED -> "boot_self_signed"
            !isPatchRecent(parsed.osPatchLevel, nowEpochMs) -> "patch_too_old"
            else -> "strong_unmet"
        }
    }

    val app = computeAppRecognition(
        f10Report,
        parsed,
        runtimePackageName,
        runtimeSignerCertSha256,
    )

    val severity = when {
        // Software-only attestation OR app-recognition mismatch is the
        // strongest signal we can produce on-device — no MEETS_BASIC_INTEGRITY
        // means there is no hardware-backed evidence at all.
        !isHardware -> Severity.CRITICAL
        app == AppRecognition.UNRECOGNIZED_VERSION -> Severity.CRITICAL
        !isGenuineOs -> Severity.HIGH
        !isStrong -> Severity.MEDIUM
        else -> Severity.LOW
    }

    // If app_recognition flagged a mismatch but we hadn't already noted
    // a device-side failure, surface it as the verdict's reason. Device-
    // side failures take precedence because they're more actionable.
    val reason = firstFailure
        ?: if (app == AppRecognition.UNRECOGNIZED_VERSION) "app_identity_mismatch" else null

    return IntegrityVerdict(
        deviceRecognition = tiers,
        appRecognition = app,
        severity = severity,
        reason = reason,
    )
}

private fun computeAppRecognition(
    f10: DetectorReport?,
    parsed: ParsedKeyDescription,
    runtimePackageName: String,
    runtimeSignerCertSha256: List<String>,
): AppRecognition {
    if (f10 == null) return AppRecognition.UNEVALUATED
    if (f10.status != DetectorStatus.OK) return AppRecognition.UNEVALUATED
    // F10 producing any finding (regardless of kind) means the running
    // APK does not match the build-time fingerprint exactly. That's the
    // textbook "UNRECOGNIZED_VERSION" signal.
    if (f10.findings.isNotEmpty()) return AppRecognition.UNRECOGNIZED_VERSION

    val attestedPkg = parsed.attestedPackageName
    if (attestedPkg != null && attestedPkg != runtimePackageName) {
        return AppRecognition.UNRECOGNIZED_VERSION
    }

    val attestedSet = parsed.attestedSignerDigestsHex.map { it.lowercase() }.toSet()
    if (attestedSet.isEmpty()) {
        // No digests to compare against — F10 is clean so we don't
        // want to *downgrade* to UNRECOGNIZED_VERSION; mark UNEVALUATED
        // so the backend can decide.
        return AppRecognition.UNEVALUATED
    }
    val runtimeSet = runtimeSignerCertSha256.map { it.lowercase() }.toSet()
    if (runtimeSet.isEmpty()) return AppRecognition.UNEVALUATED
    return if (attestedSet.intersect(runtimeSet).isNotEmpty()) {
        AppRecognition.RECOGNIZED
    } else {
        AppRecognition.UNRECOGNIZED_VERSION
    }
}

/**
 * True if [patchLevelYYYYMMDD] is within [MAX_PATCH_AGE_DAYS] of
 * [nowEpochMs]. The KeyDescription patch-level field is encoded as
 * `YYYYMM` (with day omitted) on KeyMaster 4, and `YYYYMMDD` on
 * KeyMaster 4.1+. We accept both: missing day defaults to the
 * first of the month.
 */
private fun isPatchRecent(patchLevelYYYYMMDD: Int?, nowEpochMs: Long): Boolean {
    if (patchLevelYYYYMMDD == null || patchLevelYYYYMMDD <= 0) return false
    val yyyymmdd = if (patchLevelYYYYMMDD < 1_000_000) {
        // YYYYMM form (KM 4) — promote to YYYYMM01.
        patchLevelYYYYMMDD * 100 + 1
    } else {
        patchLevelYYYYMMDD
    }
    val year = yyyymmdd / 10_000
    val month = (yyyymmdd / 100) % 100
    val day = yyyymmdd % 100
    val effectiveDay = if (day == 0) 1 else day
    if (year !in 2000..3000 || month !in 1..12 || effectiveDay !in 1..31) return false

    val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
    cal.clear()
    cal.set(year, month - 1, effectiveDay, 0, 0, 0)
    val patchMs = cal.timeInMillis
    val ageDays = (nowEpochMs - patchMs) / (24L * 3600L * 1000L)
    return ageDays in 0..MAX_PATCH_AGE_DAYS
}
