package io.ssemaj.deviceintelligence.internal

import android.annotation.SuppressLint
import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import io.ssemaj.deviceintelligence.AttestationReport
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * F14 — hardware-backed key attestation detector.
 *
 * Asks the on-device TEE / StrongBox (via [AndroidKeyStore]) to issue
 * an attested EC keypair. The resulting X.509 cert chain carries a
 * `KeyDescription` extension (OID `1.3.6.1.4.1.11129.2.1.17`) that
 * the TEE itself populates with facts userland cannot lie about:
 * Verified Boot state, bootloader-locked flag, OS / vendor / boot
 * patch levels, and the package + signer that owns the attested key.
 *
 * **Where its output lives:**
 *
 *  - The **raw evidence** (cert chain + parsed KeyDescription fields)
 *    is shipped on every report at
 *    `app.attestation` ([AttestationReport]). It lives there rather
 *    than as a [Finding] inside this detector's report because it is
 *    not an *anomaly* signal — every successful keygen produces it,
 *    even on perfectly clean devices. Backends need it on every
 *    report to perform authoritative server-side re-verification.
 *  - The **advisory verdict** ([IntegrityVerdict]) is shipped twice:
 *    its summary fields ride along on `app.attestation`
 *    (`verdict_device_recognition`, `verdict_app_recognition`,
 *    `verdict_reason`, `verdict_authoritative`), AND a
 *    `tee_integrity_verdict` [Finding] is emitted **only when the
 *    verdict is degraded** (severity > LOW). On a clean device, F14
 *    contributes zero findings — matching the rest of the library's
 *    "no news is good news" pattern.
 *
 * Lifecycle:
 *  - Cached for the lifetime of the process; the chain is bound to
 *    the boot session via Verified Boot state and patch levels, so
 *    a process-lifetime cache is structurally correct.
 *  - The cold-start cost (typically 80–500ms TEE / 0.5–4s StrongBox)
 *    is absorbed by the background pre-warm that
 *    [DeviceIntelligenceInitProvider] performs at process start.
 *  - User-facing `collect()` reads the cache and returns in
 *    single-digit ms after the first call.
 *
 * Failure-mode policy (mirrors the rest of the library):
 *  - Pre-API 28 → `INCONCLUSIVE` reason `api_too_low`, and
 *    `app.attestation` is `null` on the report (the device does not
 *    support hardware attestation at all).
 *  - On API 28+ but the keystore couldn't run → `INCONCLUSIVE` with
 *    one of `attestation_not_supported`, `keystore_error`,
 *    `keystore_unavailable`. `app.attestation` is non-null with
 *    [AttestationReport.unavailableReason] populated and the parsed
 *    fields all null — backends always see the same shape.
 *  - Chain retrieved but extension parse failed → `OK` with no
 *    findings. `app.attestation.chainB64` carries the raw chain so
 *    a backend can do the work from the bytes.
 *
 * Stays declared as `object` for cache locality; identical pattern
 * to [EmulatorProbe] and [ClonerDetector].
 */
/**
 * Result of one attested keystore generation pass. Top-level so
 * sibling detectors (F15 [BootloaderIntegrityDetector]) can read it
 * via [KeyAttestationDetector.lastResult] without duplicating the
 * keystore plumbing.
 *
 * [Success.rawCerts], [Success.keyStorePublicKeyEncoded], and
 * [Success.nonce] are not part of the F14 wire contract — they exist
 * specifically so cross-check detectors can compare two attestation
 * results structurally without re-decoding the base64 chain bytes
 * the F14 finding ships.
 */
internal sealed class AttestationResult {
    data class Success(
        val chainB64: String,
        val chainLength: Int,
        val parsed: ParsedKeyDescription?,
        /** Decoded cert chain (leaf -> root), kept for sibling cross-checks. */
        val rawCerts: List<X509Certificate>,
        /** Encoded public key actually held in the AndroidKeyStore for this alias. */
        val keyStorePublicKeyEncoded: ByteArray?,
        /** Nonce we asked the TEE to embed; used by sibling detectors for challenge-echo checks. */
        val nonce: ByteArray,
    ) : AttestationResult() {
        // Suppress equals/hashCode — ByteArray fields would do identity comparison
        // anyway, and we don't actually use equality on this type.
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    data class Failure(val reason: String, val message: String) : AttestationResult()
}

internal object KeyAttestationDetector : Detector {

    private const val TAG = "DeviceIntelligence.KeyAttestation"

    /**
     * Versioned alias so we can rotate the key in a future release
     * without colliding with prior installs that left a `.v0` lying
     * around. F15 owns its own alias under the same versioned-prefix
     * convention.
     */
    private const val ALIAS_F14 = "io.ssemaj.deviceintelligence.f14.attestation.v1"
    internal const val ANDROID_KEY_STORE = "AndroidKeyStore"

    /**
     * 32 bytes of randomness is what Play Integrity itself
     * recommends for nonces. The challenge ends up echoed verbatim
     * inside the attested cert, so a backend can pin freshness
     * against a per-session value if desired.
     */
    internal const val NONCE_LEN = 32

    override val id: String = "F14.key_attestation"

    @Volatile
    private var cached: AttestationResult? = null
    private val lock = Any()

    /**
     * Read the cached F14 attestation result, or null if F14 has not
     * yet produced one in this process. Used by sibling detectors
     * (F15) to share F14's chain bytes without doing a redundant
     * keygen of their own.
     */
    internal fun lastResult(): AttestationResult.Success? =
        cached as? AttestationResult.Success

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return inconclusive(
                id = id,
                reason = "api_too_low",
                message = "Hardware key attestation requires Android 9 (API 28) or newer",
                durationMs = dur(),
            )
        }

        val pkg = ctx.applicationContext.packageName.orEmpty()
        if (pkg.isEmpty()) {
            return inconclusive(
                id = id,
                reason = "missing_package_name",
                message = "context.packageName was null/empty",
                durationMs = dur(),
            )
        }

        val result = synchronized(lock) {
            cached ?: runChainForAlias(ALIAS_F14, freshNonce()).also { cached = it }
        }

        return when (result) {
            is AttestationResult.Failure -> inconclusive(id, result.reason, result.message, dur())
            is AttestationResult.Success -> ok(id, buildFindings(result, ctx, pkg), dur())
        }
    }

    /**
     * Build the [AttestationReport] that ships at `app.attestation` on
     * every report (when API 28+).
     *
     * Called by [TelemetryCollector] *after* this detector has run,
     * which guarantees the cache is populated (or set to a Failure
     * value if keygen flopped). The collector also passes the live
     * F10 report and runtime signer hashes so the wire-shipped
     * advisory verdict matches the one F14's finding-emission path
     * would produce — same single source of truth.
     *
     * Returns:
     *  - `null` on pre-API 28 (the device doesn't support hardware
     *    attestation at all).
     *  - [AttestationReport] with [AttestationReport.unavailableReason]
     *    populated when keygen failed (e.g. stripped AOSP / no-TEE
     *    emulator).
     *  - Fully populated [AttestationReport] on success.
     */
    internal fun toAttestationReport(
        detectorReport: DetectorReport,
        f10Report: DetectorReport?,
        runtimePackageName: String,
        runtimeSignerCertSha256: List<String>,
    ): AttestationReport? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return when (val c = synchronized(lock) { cached }) {
            is AttestationResult.Success -> buildSuccessReport(
                c = c,
                f10Report = f10Report,
                runtimePackageName = runtimePackageName,
                runtimeSignerCertSha256 = runtimeSignerCertSha256,
            )
            is AttestationResult.Failure -> emptyAttestationReport(c.reason)
            null -> emptyAttestationReport(
                detectorReport.inconclusiveReason ?: "not_attempted",
            )
        }
    }

    /** Only-when-degraded verdict finding is computed against the same context as [evaluate]. */
    private fun shouldEmitVerdictFinding(verdict: IntegrityVerdict): Boolean =
        verdict.severity != Severity.LOW

    /** Generate a fresh per-call attestation nonce. */
    internal fun freshNonce(): ByteArray =
        ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }

    /**
     * Generate the attested EC keypair under [alias] with [nonce],
     * fetch the cert chain, parse the leaf's KeyDescription extension.
     * Returns either an [AttestationResult.Success] wrapping all of
     * that, or an [AttestationResult.Failure] carrying the inconclusive
     * reason for the surrounding evaluate().
     *
     * Prefers StrongBox when available; falls back to the default
     * TEE provider on [StrongBoxUnavailableException]. The actual
     * security level achieved is reported via the parsed
     * `attestation_security_level` field — we do not pretend
     * StrongBox happened when it didn't.
     *
     * Parameterised so F15's [BootloaderIntegrityDetector] can call
     * the same plumbing with its own alias + nonce for the second-
     * attestation freshness check.
     */
    @SuppressLint("NewApi")
    internal fun runChainForAlias(alias: String, nonce: ByteArray): AttestationResult {
        val keyStore = try {
            KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        } catch (t: Throwable) {
            Log.w(TAG, "AndroidKeyStore unavailable", t)
            return AttestationResult.Failure(
                "keystore_unavailable",
                "AndroidKeyStore.getInstance failed: ${t.javaClass.simpleName}",
            )
        }

        // Clean slate: a stale alias from a prior boot session would
        // have a stale challenge embedded in its cert, so always
        // regenerate. Failure here is fine — alias may simply not
        // exist yet on first run.
        runCatching { keyStore.deleteEntry(alias) }

        try {
            generateKeyPair(alias, nonce, preferStrongBox = true)
        } catch (sbu: StrongBoxUnavailableException) {
            Log.i(TAG, "StrongBox unavailable for $alias, falling back to default TEE provider")
            try {
                generateKeyPair(alias, nonce, preferStrongBox = false)
            } catch (t: Throwable) {
                return mapKeyGenFailure(t)
            }
        } catch (t: Throwable) {
            return mapKeyGenFailure(t)
        }

        val rawChain = try {
            keyStore.getCertificateChain(alias)
        } catch (t: Throwable) {
            Log.w(TAG, "getCertificateChain threw", t)
            return AttestationResult.Failure(
                "keystore_error",
                "getCertificateChain threw: ${t.javaClass.simpleName}",
            )
        }

        if (rawChain == null || rawChain.isEmpty()) {
            return AttestationResult.Failure(
                "attestation_not_supported",
                "AndroidKeyStore returned no certificate chain for the attested alias",
            )
        }

        // Encode every cert as base64; pipe-separate so the whole
        // chain travels as a single string entry inside Finding.details
        // (which is `Map<String, String>` by contract).
        val encoder = Base64.getEncoder()
        val chainB64 = buildString(rawChain.size * 1024) {
            for (i in rawChain.indices) {
                if (i > 0) append('|')
                append(encoder.encodeToString(rawChain[i].encoded))
            }
        }

        // Cast every cert in the chain to X509Certificate; in practice
        // every entry from AndroidKeyStore is already an X509 — the
        // filter is defensive against a vendor that returns a non-X509
        // implementation, in which case downstream cross-checks
        // gracefully degrade (cert verification just doesn't run).
        val x509Chain: List<X509Certificate> = rawChain.mapNotNull { it as? X509Certificate }

        val leaf = x509Chain.firstOrNull()
        val parsed = leaf?.let {
            val ext = runCatching { it.getExtensionValue(KeyDescriptionParser.OID) }
                .getOrNull()
            if (ext != null) KeyDescriptionParser.parse(ext) else null
        }

        // Read the public key the AndroidKeyStore actually holds for
        // this alias; F15 compares this against the leaf cert's
        // SubjectPublicKey to catch chains that were generated for a
        // different key (a particular flavour of cached-chain forgery).
        val keyStorePubKeyEncoded = runCatching {
            keyStore.getCertificate(alias)?.publicKey?.encoded
        }.getOrNull()

        Log.i(
            TAG,
            "attested chain ready for $alias: chainLen=${rawChain.size} parsedOk=${parsed != null}",
        )
        return AttestationResult.Success(
            chainB64 = chainB64,
            chainLength = rawChain.size,
            parsed = parsed,
            rawCerts = x509Chain,
            keyStorePublicKeyEncoded = keyStorePubKeyEncoded,
            nonce = nonce,
        )
    }

    @SuppressLint("NewApi")
    private fun generateKeyPair(alias: String, nonce: ByteArray, preferStrongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(nonce)
        if (preferStrongBox) builder.setIsStrongBoxBacked(true)
        val gen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        )
        gen.initialize(builder.build())
        gen.generateKeyPair()
    }

    private fun mapKeyGenFailure(t: Throwable): AttestationResult.Failure {
        val msg = (t.message ?: "").lowercase()
        // KeyStoreException's message text is the only signal Android
        // gives us for "this device has no attestation implementation."
        // Fall back on a generic keystore_error reason for anything
        // else — backends can still inspect error_message for forensics.
        val reason = when {
            "attestation challenges not supported" in msg ||
                "not supported" in msg && "attestation" in msg -> "attestation_not_supported"
            else -> "keystore_error"
        }
        Log.w(TAG, "key generation failed: reason=$reason", t)
        return AttestationResult.Failure(
            reason,
            "${t.javaClass.simpleName}: ${t.message ?: "<no message>"}",
        )
    }

    // ---- finding construction ---------------------------------------------

    /**
     * Emits the `tee_integrity_verdict` advisory finding **only when
     * the verdict is degraded** (severity > LOW). On a clean device,
     * F14 contributes zero findings to the report — the raw chain +
     * full verdict still ride along on `app.attestation`.
     */
    private fun buildFindings(
        c: AttestationResult.Success,
        ctx: DetectorContext,
        pkg: String,
    ): List<Finding> {
        val verdict = computeVerdict(c, ctx, pkg)
        return if (shouldEmitVerdictFinding(verdict)) {
            listOf(buildVerdictFinding(c, verdict, pkg))
        } else {
            emptyList()
        }
    }

    private fun computeVerdict(
        c: AttestationResult.Success,
        ctx: DetectorContext,
        pkg: String,
    ): IntegrityVerdict = deriveIntegrityVerdict(
        parsed = c.parsed,
        f10Report = ctx.f10Report,
        runtimePackageName = pkg,
        runtimeSignerCertSha256 = readRuntimeSignerHashes(ctx),
        nowEpochMs = System.currentTimeMillis(),
    )

    private fun buildVerdictFinding(
        c: AttestationResult.Success,
        verdict: IntegrityVerdict,
        pkg: String,
    ): Finding {
        val details = LinkedHashMap<String, String>(8)
        details["device_recognition"] = verdict.deviceRecognition
            .joinToString(",") { it.wire }
        details["app_recognition"] = verdict.appRecognition.wire
        details["bootloader_locked"] = (c.parsed?.deviceLocked?.toString() ?: "unknown")
        details["verified_boot_state"] = c.parsed?.verifiedBootState?.wire ?: "Unknown"
        details["verdict_authoritative"] = "false"
        verdict.reason?.let { details["reason"] = it }

        return Finding(
            kind = "tee_integrity_verdict",
            severity = verdict.severity,
            subject = pkg,
            message = "TEE evidence indicates degraded device or app integrity (advisory; verify chain server-side)",
            details = details,
        )
    }

    // ---- AttestationReport construction -----------------------------------

    /**
     * Build a fully populated [AttestationReport] from a cached
     * successful keygen. The verdict is derived against the SAME
     * live context the finding-emission path uses (F10's report,
     * runtime signer hashes, runtime package), so the
     * `verdict_*` fields on `app.attestation` always agree with
     * any `tee_integrity_verdict` finding emitted in the same
     * `collect()` pass.
     */
    private fun buildSuccessReport(
        c: AttestationResult.Success,
        f10Report: DetectorReport?,
        runtimePackageName: String,
        runtimeSignerCertSha256: List<String>,
    ): AttestationReport {
        val p = c.parsed
        val verdict = deriveIntegrityVerdict(
            parsed = p,
            f10Report = f10Report,
            runtimePackageName = runtimePackageName,
            runtimeSignerCertSha256 = runtimeSignerCertSha256,
            nowEpochMs = System.currentTimeMillis(),
        )
        return AttestationReport(
            chainB64 = c.chainB64,
            chainSha256 = sha256HexOfAscii(c.chainB64),
            chainLength = c.chainLength,
            attestationSecurityLevel = p?.attestationSecurityLevel?.wire,
            keymasterSecurityLevel = p?.keymasterSecurityLevel?.wire,
            keymasterVersion = p?.keymasterVersion,
            attestationChallengeB64 = p?.attestationChallenge?.let {
                Base64.getEncoder().encodeToString(it)
            },
            verifiedBootState = p?.verifiedBootState?.wire,
            deviceLocked = p?.deviceLocked,
            verifiedBootKeySha256 = p?.verifiedBootKey?.let { sha256Hex(it) },
            osVersion = p?.osVersion,
            osPatchLevel = p?.osPatchLevel,
            vendorPatchLevel = p?.vendorPatchLevel,
            bootPatchLevel = p?.bootPatchLevel,
            attestedPackageName = p?.attestedPackageName,
            attestedApplicationIdSha256 = p?.attestationApplicationIdRaw?.let { sha256Hex(it) },
            attestedSignerCertSha256 = p?.attestedSignerDigestsHex.orEmpty(),
            verdictDeviceRecognition = verdict.deviceRecognition.joinToString(",") { it.wire },
            verdictAppRecognition = verdict.appRecognition.wire,
            verdictReason = verdict.reason,
            verdictAuthoritative = false,
            unavailableReason = null,
        )
    }

    private fun emptyAttestationReport(reason: String): AttestationReport = AttestationReport(
        chainB64 = null,
        chainSha256 = null,
        chainLength = 0,
        attestationSecurityLevel = null,
        keymasterSecurityLevel = null,
        keymasterVersion = null,
        attestationChallengeB64 = null,
        verifiedBootState = null,
        deviceLocked = null,
        verifiedBootKeySha256 = null,
        osVersion = null,
        osPatchLevel = null,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        attestedPackageName = null,
        attestedApplicationIdSha256 = null,
        attestedSignerCertSha256 = emptyList(),
        verdictDeviceRecognition = null,
        verdictAppRecognition = null,
        verdictReason = null,
        verdictAuthoritative = false,
        unavailableReason = reason,
    )

    /**
     * Read the runtime signer-cert SHA-256s the same way
     * [TelemetryCollector] does for `AppContext.signerCertSha256`,
     * so the F14 cross-check uses bytes that are identical to what
     * the rest of the report carries. Returns empty (not null) on
     * any failure path so the verdict downgrades to `UNEVALUATED`
     * rather than `UNRECOGNIZED_VERSION`.
     */
    private fun readRuntimeSignerHashes(ctx: DetectorContext): List<String> {
        if (!ctx.nativeReady) return emptyList()
        val apkPath = ctx.applicationContext.applicationInfo?.sourceDir ?: return emptyList()
        return runCatching { NativeBridge.apkSignerCertHashes(apkPath) }
            .getOrNull()?.toList().orEmpty()
    }

    // ---- shared helper -----------------------------------------------------

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return KeyDescriptionParser.hexLower(md.digest(bytes))
    }

    /**
     * SHA-256 hex of the ASCII bytes of a string. Used for the
     * `chain_sha256` correlation key on the JSON wire format —
     * hashes the same `chainB64` string that backends would receive,
     * so a backend that DOES upload the chain bytes can independently
     * reproduce the hash for sanity checking.
     */
    private fun sha256HexOfAscii(s: String): String =
        sha256Hex(s.toByteArray(Charsets.US_ASCII))

    /** Test-only: drop the cached chain so the next [evaluate] re-runs the keystore call. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
