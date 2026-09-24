package tech.thessemaj.deviceintelligence.gradle.internal

/**
 * F3 gate (2026-09-10 spec): a release build must never silently ship with the
 * native signer baseline stubbed (`DICORE_BASELINE_ENABLED 0`). Either the
 * integrator pins `-Pdeviceintelligence.expectedSigner=<sha256-hex>` or they opt out
 * explicitly with `-Pdeviceintelligence.signerBaseline.skip=<any value>` — the absence of
 * both is a build break, not a stub.
 */
internal object SignerBaselineGate {
    object Allow
    data class AllowDeferred(val reason: String)
    data class Fail(val reason: String)

    fun decide(expectedSigner: String?, skip: String?): Any =
        when {
            !expectedSigner.isNullOrBlank() -> Allow
            skip != null -> AllowDeferred(
                "signer baseline intentionally skipped (deviceintelligence.signerBaseline.skip=$skip) — " +
                    "release integrity anchor is the server-side attestation pin only")
            else -> Fail(
                "release build needs -Pdeviceintelligence.expectedSigner=<signer-cert-sha256-hex> " +
                    "or an explicit -Pdeviceintelligence.signerBaseline.skip=<any> opt-out — " +
                    "a silently-stubbed signer baseline ships an unfakeable-check-free artifact")
        }
}
