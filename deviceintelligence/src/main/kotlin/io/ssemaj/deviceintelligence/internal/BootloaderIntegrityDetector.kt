package io.ssemaj.deviceintelligence.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import java.security.cert.X509Certificate

/**
 * `integrity.bootloader` — bootloader integrity / TEE-attestation
 * tamper detector.
 *
 * `attestation.key` ([KeyAttestationDetector]) faithfully reports
 * what the on-device TEE *claims*. That is the whole point of
 * `attestation.key`, and is what makes its raw `cert_chain_b64`
 * the only authoritative signal — once a backend verifies the
 * chain against Google's pinned root + revocation list.
 *
 * The problem `integrity.bootloader` solves is that on a
 * Magisk-style root with Tricky Store / LSPosed installed, the
 * attacker can hook the AndroidKeyStore surface to return a
 * *previously captured* chain from a clean boot session.
 * `attestation.key` sees a well-formed chain, parses it, and
 * dutifully reports `device_locked = true` even though the
 * userland reports the bootloader as unlocked.
 *
 * `integrity.bootloader` raises the cost of that bypass by
 * running orthogonal cross-checks that a cache-replay forgery
 * struggles to satisfy simultaneously:
 *
 *  1. **Freshness across two attestations** — generates a *second*
 *     attestation under a fresh alias + nonce, and compares it
 *     structurally to `attestation.key`'s. Two consecutive keygens
 *     on the same boot session MUST produce different leaf
 *     SubjectPublicKeys (we asked for two distinct EC keys) and
 *     MUST embed two distinct attestation challenges (we sent two
 *     different nonces). A cache-replay forgery typically returns
 *     the same leaf for every keygen call.
 *  2. **Challenge echo** — the leaf cert MUST embed the exact nonce
 *     we asked the TEE to attest. If it doesn't, the chain was
 *     minted for some other request.
 *  3. **Leaf pubkey matches keystore key** — the leaf cert's
 *     SubjectPublicKey MUST equal the public key the AndroidKeyStore
 *     actually holds for our alias. A naive cached chain serves
 *     someone else's pubkey here.
 *  4. **Chain structural validity** — every cert in the chain must
 *     verify against its issuer; the root must self-sign. Lazy
 *     forgers cut corners on signatures (intermediate windows are
 *     not checked for nesting — see [ChainValidator] for why that
 *     check was unsound and got removed).
 *  5. **StrongBox unexpectedly unavailable** — devices that should
 *     expose a StrongBox-class secure element MUST attest with
 *     security level `STRONG_BOX`. The detector triggers when EITHER
 *     the platform self-reports `FEATURE_STRONGBOX_KEYSTORE`
 *     (the canonical OEM-agnostic capability flag) OR the device
 *     matches the hardcoded Pixel-3+ denylist (paranoid fallback for
 *     when an attacker also hooks the PackageManager feature surface
 *     to hide StrongBox), AND the actual attestation comes back as
 *     `TRUSTED_ENVIRONMENT` or `SOFTWARE`. Attackers can't fake
 *     Titan M signatures, so they usually downgrade to TEE attestation
 *     only — making this a load-bearing tamper signal.
 *
 * Output policy (defense-in-depth):
 *  - On a clean device, `integrity.bootloader` emits **zero
 *    findings**. The detector is silent unless something specific
 *    tripped.
 *  - Each tripped check emits its own `bootloader_integrity_anomaly`
 *    Finding with a stable `subreason` code in `details`. Backends
 *    pivot on `subreason`.
 *  - StrongBox unavailability emits a separate
 *    `bootloader_strongbox_unavailable` finding (different
 *    semantics — could legitimately be flaky hardware, hence
 *    MEDIUM severity rather than HIGH).
 *
 * Cost:
 *  - One additional attestation keygen per process (50–500ms TEE,
 *    0.5–4s StrongBox). Cached for the rest of the process lifetime,
 *    same as `attestation.key`.
 *  - Pure cross-check functions (see [ChainValidator]) on top of the
 *    two cached chains — sub-millisecond.
 *
 * Failure-mode policy:
 *  - `attestation.key` didn't cache a result → INCONCLUSIVE
 *    `attestation_key_unavailable`.
 *  - This detector's own keygen failed → INCONCLUSIVE with the same
 *    failure-reason vocabulary `attestation.key` uses
 *    (`attestation_not_supported`, `keystore_error`,
 *    `keystore_unavailable`).
 *  - The detector itself never throws.
 *
 * Authority caveat: like `attestation.key`'s verdict finding, every
 * `integrity.bootloader` finding carries
 * `verdict_authoritative = "false"`. The library does not consider
 * these signals authoritative — they are *advisory*. The
 * authoritative verdict still comes from a backend that re-verifies
 * `attestation.key`'s `cert_chain_b64` against Google's root +
 * revocation list + fleet-wide correlation.
 */
internal object BootloaderIntegrityDetector : Detector {

    private const val TAG = "DeviceIntelligence.BootloaderIntegrity"

    /**
     * Distinct from [KeyAttestationDetector]'s alias so the two
     * keygens are independent on the keystore side. Versioned for
     * future rotation parity with `attestation.key`.
     *
     * The literal still contains `f15` for backwards compatibility
     * (see KeyAttestationDetector.ATTESTATION_KEY_ALIAS for
     * rationale): renaming the alias string would orphan keys
     * generated by earlier versions of the library.
     */
    private const val BOOTLOADER_KEY_ALIAS = "io.ssemaj.deviceintelligence.f15.bootloader.v1"

    override val id: String = "integrity.bootloader"

    @Volatile
    private var cached: Cached? = null
    private val lock = Any()

    private sealed class Cached {
        /** Cross-checks ran. [outcomes] is empty on a clean device, populated on tamper. */
        data class Success(val outcomes: List<CheckOutcome>) : Cached()
        data class Failure(val reason: String, val message: String) : Cached()
    }

    /** One tripped cross-check: stable [subreason] + a [Finding] payload. */
    private data class CheckOutcome(
        val subreason: String,
        val severity: Severity,
        val kind: String,
        val message: String,
        val extraDetails: Map<String, String> = emptyMap(),
    )

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

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
            cached ?: computeOnce(ctx.applicationContext).also { cached = it }
        }

        return when (result) {
            is Cached.Failure -> inconclusive(id, result.reason, result.message, dur())
            is Cached.Success -> ok(id, buildFindings(result.outcomes, pkg), dur())
        }
    }

    /**
     * Run this detector's own attestation, then collect all cross-check
     * outcomes against `attestation.key`'s cached attestation. Called
     * at most once per process; subsequent [evaluate] calls hit
     * [cached].
     */
    private fun computeOnce(appContext: Context): Cached {
        val primary = KeyAttestationDetector.lastResult()
            ?: return Cached.Failure(
                "attestation_key_unavailable",
                "attestation.key has not produced a cached attestation result in this process",
            )

        val nonce = KeyAttestationDetector.freshNonce()
        val secondaryResult = KeyAttestationDetector.runChainForAlias(BOOTLOADER_KEY_ALIAS, nonce)
        if (secondaryResult is AttestationResult.Failure) {
            return Cached.Failure(secondaryResult.reason, secondaryResult.message)
        }
        val secondary = secondaryResult as AttestationResult.Success

        val outcomes = ArrayList<CheckOutcome>()

        // ---- structural ----
        addOutcomeIfTripped(outcomes, ChainValidator.validateStructure(primary.rawCerts)) { sub ->
            CheckOutcome(
                subreason = sub,
                severity = Severity.HIGH,
                kind = KIND_INTEGRITY,
                message = "TEE attestation chain has anomalous structure (${describeStructure(sub)})",
                extraDetails = mapOf("chain_length" to primary.rawCerts.size.toString()),
            )
        }
        addOutcomeIfTripped(outcomes, ChainValidator.verifyChainSignatures(primary.rawCerts)) { sub ->
            CheckOutcome(
                subreason = sub,
                severity = Severity.HIGH,
                kind = KIND_INTEGRITY,
                message = "TEE attestation chain failed signature verification ($sub)",
            )
        }
        // ---- freshness ----
        addOutcomeIfTripped(outcomes, ChainValidator.challengeEchoes(primary.parsed, primary.nonce)) { sub ->
            CheckOutcome(
                subreason = sub,
                severity = Severity.HIGH,
                kind = KIND_INTEGRITY,
                message = "TEE attestation chain does not echo the challenge nonce we sent — chain is forged or replayed",
            )
        }
        addOutcomeIfTripped(outcomes, ChainValidator.freshnessAcrossAttestations(primary, secondary)) { sub ->
            CheckOutcome(
                subreason = sub,
                severity = Severity.HIGH,
                kind = KIND_INTEGRITY,
                message = "Two consecutive TEE attestations are suspiciously similar — keystore is replaying a cached chain ($sub)",
            )
        }

        // ---- consistency ----
        val leaf = primary.rawCerts.firstOrNull()
        if (leaf != null) {
            addOutcomeIfTripped(
                outcomes,
                ChainValidator.leafPubKeyMatchesKeystoreKey(leaf, primary.keyStorePublicKeyEncoded),
            ) { sub ->
                CheckOutcome(
                    subreason = sub,
                    severity = if (sub == "leaf_pubkey_unreadable") Severity.MEDIUM else Severity.HIGH,
                    kind = KIND_INTEGRITY,
                    message = "TEE attestation leaf cert pubkey does not match the keystore-held key for our alias",
                )
            }
        }

        // ---- StrongBox-required denylist ----
        // Devices that should expose a StrongBox-class secure element
        // MUST attest with security level STRONG_BOX. Anything else
        // means the StrongBox surface was bypassed (Tricky Store
        // can't fake Titan M / discrete-SE signatures and downgrades
        // to TEE attestation only). Two complementary triggers:
        //
        //   1. Platform self-reports FEATURE_STRONGBOX_KEYSTORE — the
        //      canonical OEM-agnostic capability flag (Android 9+).
        //   2. The Pixel-3+ hardcoded denylist — a paranoid fallback
        //      for the case where an attacker also hooked the
        //      PackageManager feature surface to hide StrongBox.
        //
        // Either trigger is enough to fire the finding, but we prefer
        // the platform flag in the diagnostics (it's what backends
        // can pivot on — `device.strongbox_available`).
        val platformStrongBox = runCatching {
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        }.getOrDefault(false)
        val pixelStrongBox = expectsStrongBox()
        if (platformStrongBox || pixelStrongBox) {
            val actual = primary.parsed?.attestationSecurityLevel
            if (actual != null && actual != SecurityLevel.STRONG_BOX) {
                outcomes += CheckOutcome(
                    subreason = "strongbox_unexpectedly_unavailable",
                    // MEDIUM not HIGH: StrongBox can be temporarily
                    // unavailable due to genuine hardware issues.
                    // Repeated trip across the fleet is what makes it
                    // damning — that's a backend correlation job.
                    severity = Severity.MEDIUM,
                    kind = KIND_STRONGBOX,
                    message = "Device advertises StrongBox capability (platform=$platformStrongBox, pixel_denylist=$pixelStrongBox) but TEE attestation came back at security level ${actual.wire} — StrongBox surface may have been bypassed",
                    extraDetails = mapOf(
                        "device_model" to (Build.MODEL ?: ""),
                        "attestation_security_level" to actual.wire,
                        "strongbox_platform_available" to platformStrongBox.toString(),
                        "strongbox_pixel_denylist_match" to pixelStrongBox.toString(),
                    ),
                )
            }
        }

        Log.i(
            TAG,
            "ran: tripped=${outcomes.size} subreasons=${outcomes.joinToString(",") { it.subreason }}",
        )
        return Cached.Success(outcomes)
    }

    private inline fun addOutcomeIfTripped(
        sink: MutableList<CheckOutcome>,
        subreason: String?,
        build: (String) -> CheckOutcome,
    ) {
        if (subreason != null) sink += build(subreason)
    }

    // ---- finding construction ---------------------------------------------

    private fun buildFindings(outcomes: List<CheckOutcome>, pkg: String): List<Finding> {
        if (outcomes.isEmpty()) return emptyList()
        return outcomes.map { o ->
            val details = LinkedHashMap<String, String>(4 + o.extraDetails.size)
            details["subreason"] = o.subreason
            details["verdict_authoritative"] = "false"
            details.putAll(o.extraDetails)
            Finding(
                kind = o.kind,
                severity = o.severity,
                subject = pkg,
                message = o.message,
                details = details,
            )
        }
    }

    // ---- helpers ----------------------------------------------------------

    private fun describeStructure(sub: String): String = when (sub) {
        "chain_empty" -> "chain is empty"
        "chain_too_short" -> "chain has fewer than 2 certs"
        else -> sub
    }

    /**
     * StrongBox-required denylist: Pixel 3 onwards ship Titan M / M2
     * and MUST attest at STRONG_BOX security level. Earlier Pixels,
     * non-Pixels, and ambiguous Pixel models (Tablet / Fold) are
     * skipped to avoid false positives.
     */
    private fun expectsStrongBox(): Boolean {
        val m = Build.MODEL ?: return false
        if (!m.startsWith("Pixel ", ignoreCase = true)) return false
        val rest = m.removePrefix("Pixel ").trimStart()
        val firstDigits = rest.takeWhile { it.isDigit() }
        val n = firstDigits.toIntOrNull() ?: return false
        return n >= 3
    }

    private const val KIND_INTEGRITY = "bootloader_integrity_anomaly"
    private const val KIND_STRONGBOX = "bootloader_strongbox_unavailable"

    /** Test-only: drop the cached cross-check outcomes so the next [evaluate] re-runs. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }

    /**
     * Test-only: expose the rawCerts type used by validators so
     * downstream tests don't need to import the X509Certificate API.
     */
    @Suppress("unused")
    internal fun leafOf(success: AttestationResult.Success): X509Certificate? =
        success.rawCerts.firstOrNull()
}
