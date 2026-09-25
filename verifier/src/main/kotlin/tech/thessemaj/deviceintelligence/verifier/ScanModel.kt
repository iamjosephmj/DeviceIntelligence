package tech.thessemaj.deviceintelligence.verifier

/**
 * The scan/session side of the model: the facts a bootstrap establishes, the
 * session the CALLER carries between scans, and the outcome of one scan.
 * (The verify/decision vocabulary — Decision, Check, ResolvedSignal,
 * VerificationResult — lives in Model.kt; the tunable backend rules in Policy.kt.)
 */

/**
 * Attested hardware security level, mapped from the KeyDescription `securityLevel`
 * (0 Software / 1 TrustedEnvironment / 2 StrongBox).
 *
 * [SOFTWARE] also covers a MISSING or unparseable securityLevel: absence is not
 * evidence of hardware, so it grades down rather than up. Before this level existed
 * everything that was not StrongBox collapsed to [TEE], which made the downstream
 * "security level >= TEE" gate vacuously true and let a software-only attestation
 * pass as hardware-backed.
 */
enum class Assurance { SOFTWARE, TEE, STRONGBOX }

data class Session(
    val pinnedKeySpkiHex: String,   // hex of the attested key's X.509 SubjectPublicKeyInfo
    val assurance: Assurance,
    val bootState: String,          // enroll-time verifiedBootState name, e.g. "Verified"
    val deviceLocked: Boolean,
    val issuedAt: Long,
    // Attestation findings extracted at enroll and carried (HMAC-signed) so the
    // per-request challenge — the call the backend adjudicates — makes the verdict.
    // enroll never rejects on these; a forgery flag drives a REJECT at challenge, a
    // failed integrity fact drives COMPROMISED. Defaults keep older sessions valid.
    val chainTrusted: Boolean = true,       // chain terminates at a pinned Google root
    val keyboxRevoked: Boolean = false,     // a serial on the attestation CRL
    val crossLevelReuse: Boolean = false,   // same batch key across StrongBox & TEE (INTEL_0016)
    val strongboxChainMissing: Boolean = false, // leaf claims StrongBox but no SB chain (INTEL_0045, fail-closed)
    val devicePropMismatch: Boolean = false,// TEE-attested identity != self-reported Build.*
    val bootStateSpoofer: Boolean = false,  // boot props claim clean, attestation says otherwise
    /**
     * The KeyDescription EXPLICITLY reported securityLevel=Software(0) — no hardware root
     * of trust (INTEL_0056). Deliberately NOT the same as `assurance == SOFTWARE`: a missing
     * or unparseable securityLevel also grades to SOFTWARE so the integrity gate fails
     * safe, but it must not raise the signal, because absence of evidence is not evidence
     * of a software keystore. This flag says only what the attestation actually proved.
     */
    val softwareAttested: Boolean = false,
)

data class EnrollResult(
    /** Whether enrollment succeeded. */
    val ok: Boolean,
    /** The established session id, when it succeeded. */
    val sessionId: String?,
    /** Every check that ran, in order. */
    val checks: List<Check>,
    /** Why it failed, when it did. */
    val reason: String?,
)

/**
 * The device fingerprint, as reported. [id] and [aid] are peppered SHA-256 hashes
 * computed on-device — the raw Widevine and ANDROID_ID values never leave the
 * handset. Every field is null when the device could not read it.
 *
 * Matching policy (which accounts sharing an [id] constitute a ring, and what to do
 * about it) belongs to the embedding service. This type only carries the facts.
 */
data class DeviceFingerprint(
    /** Peppered SHA-256 of the Widevine device id. Survives reinstall; expected to survive a flash. */
    val id: String?,
    /** Peppered SHA-256 of `ANDROID_ID`. Survives reinstall; resets on a flash. */
    val aid: String?,
    /** Widevine security level, e.g. `"L1"`. */
    val securityLevel: String?,
    /** Self-reported build fingerprint. Advisory. */
    val build: String?,
    /** Kernel release, read by raw syscall rather than through libc. */
    val kernel: String?,
    /** Self-reported security patch date. Compare against the attested value, not this one. */
    val patch: String?,
    /** Installing package, or null when sideloaded. A non-store installer is itself a signal. */
    val installer: String?,
)

/**
 * The outcome of one scan.
 *
 * Statelessness contract: on a bootstrap scan [ScanResult.attestedKey] is the SPKI
 * hex the caller MUST store on its own session record; on every later scan for that
 * session the caller passes it back as `boundKey`. No per-device store lives in
 * :verifier.
 */
/**
 * Which rung of the signing ladder a token reached.
 *
 * The device deliberately does NOT claim StrongBox vs TEE here: it cannot tell them
 * apart without parsing its own chain, and the backend derives the real assurance
 * from the certificate, which is authoritative. [ATTESTED] therefore means "a
 * hardware attestation chain is present, go and grade it"; the graded answer is
 * [ScanSession.assurance].
 */
enum class AttestationLevel {
    /** A hardware-attested key. Its actual strength is graded from the chain. */
    ATTESTED,
    /** A plain, non-attested Keystore key. Continuity only — it proves nothing. */
    SOFTWARE,
    /** No key at all. */
    NONE;

    companion object {
        /** Unknown values grade DOWN: this decodes attacker-reachable input. */
        fun parse(s: String?): AttestationLevel =
            entries.firstOrNull { it.name.equals(s, ignoreCase = true) } ?: NONE
    }
}

/**
 * What a scan token says about its own binding, present on every schemaVersion-4
 * scan from a device new enough to emit it.
 *
 * [level] describes the KEY, [signed] what actually signed THIS token; they degrade
 * independently. [reason] names why they are not `OK`, and [detail] carries the
 * machine-checkable sub-code (e.g. `strongbox_unavailable:-68`) the backend uses to
 * separate a device fault from an injection.
 *
 * On a degraded token every field here is SELF-REPORTED and unsigned, so a benign
 * [detail] can never exonerate on its own — only absence of corroborating detector
 * findings, plus cohort rarity, can. Degraded tokens incriminate reliably; they
 * exonerate only in aggregate.
 */
data class TokenAttestation(
    val level: AttestationLevel,
    val signed: AttestationLevel,
    val reason: String,
    val detail: String? = null,
) {
    /** True when this token carries no hardware-attested binding. */
    val degraded: Boolean get() = signed != AttestationLevel.ATTESTED
}

data class ScanResult(
    /**
     * Every AUTH check passed: the token is genuine and this attestation is not a
     * proven forgery. False means REJECT — do not trust the contents.
     */
    val ok: Boolean,
    /** True when this is the first scan of a cold start — the one carrying the chain. */
    val bootstrap: Boolean,
    /**
     * Every INTEGRITY check passed: the device is honestly reporting AND is in a
     * trustworthy state (hardware-backed, verified boot, locked). A token can be
     * perfectly authentic ([ok]) while this is false — that is a COMPROMISED device,
     * not a forged token.
     */
    val deviceIntegrityOk: Boolean,
    /**
     * Non-null on a successful bootstrap scan: everything the caller must store on
     * its own session record and pass back on every later scan. This is what keeps
     * the verifier stateless.
     */
    val session: ScanSession?,
    /** Every check that ran, in order. The audit trail for this decision. */
    val checks: List<Check>,
    /** Findings resolved from opaque codes to meaning. */
    val signals: List<ResolvedSignal>,
    /** Why this failed, when it did. Null on success. */
    val reason: String?,
    /** The device fingerprint, when the token carried one. */
    val fingerprint: DeviceFingerprint? = null,
    /**
     * What the token said about its own binding, or null from a client too old to
     * say. Null is NOT a degraded claim — it is the absence of one.
     */
    val attestation: TokenAttestation? = null,
) {
    /** Convenience: the attested key this session is bound to. */
    val attestedKey: String? get() = session?.attestedKey
    /** Convenience: the app identity the TEE attested at bootstrap. */
    val attestedApp: AttestedApp? get() = session?.attestedApp

    /** The findings whose [ResolvedSignal.blocking] is true — the usual step-up payload. */
    val blockingSignals: List<ResolvedSignal> get() = signals.filter { it.blocking }

    /**
     * This scan mapped onto the three decisions, using the DOCUMENTED DEFAULT policy:
     *
     * - a proven forgery ([ok] false)                                → [Decision.REJECT]
     * - an honest report of an untrustworthy device, or any blocking
     *   signal ([deviceIntegrityOk] false / [blockingSignals] non-empty) → [Decision.COMPROMISED]
     * - otherwise                                                    → [Decision.TRUSTWORTHY]
     *
     * This is the readable on-ramp for backends that just want the answer:
     *
     * ```
     * when (result.decision) {
     *     Decision.TRUSTWORTHY -> allow()
     *     Decision.COMPROMISED -> stepUp(result.blockingSignals)
     *     Decision.REJECT      -> deny(result.reason)
     * }
     * ```
     *
     * It is a CONVENIENCE, not a delegation of authority: the policy call is still
     * yours. A backend that tunes severities, tolerates specific signals, requires
     * StrongBox, or steps up on HIGH instead of only blocking signals must read the
     * graded axes ([ok], [deviceIntegrityOk], [signals]) directly and decide for
     * itself — [ScanVerifier] and this property will never silently absorb that.
     */
    val decision: Decision
        get() = when {
            !ok                                        -> Decision.REJECT
            !deviceIntegrityOk || blockingSignals.isNotEmpty() -> Decision.COMPROMISED
            else                                       -> Decision.TRUSTWORTHY
        }
}

/**
 * The attestation facts established at bootstrap, carried by the CALLER on its own
 * session record and handed back on every later scan.
 *
 * Attestation runs only at bootstrap, so without this a steady-state scan would be
 * adjudicated on its runtime detectors alone — with no idea whether the device was
 * hardware-backed, verified-boot, locked, or running a leaked keybox. That is the
 * same split the retired enroll/challenge pair used, with the signed session token
 * replaced by a plain object the caller stores.
 */
data class ScanSession(
    /** Hex SPKI of the attested key every later scan must be signed by. */
    val attestedKey: String,
    /** Package + signing digests the TEE attested (tag 709); null if absent. */
    val attestedApp: AttestedApp?,
    /** How strong the attestation actually was: StrongBox, TEE, or software. */
    val assurance: Assurance,
    /** verifiedBootState name at bootstrap, e.g. "Verified". */
    val bootState: String,
    /** Whether the bootloader reported itself locked at bootstrap. */
    val deviceLocked: Boolean,
    // --- proven forgeries: AUTH failures -> REJECT -------------------------------
    /** The chain terminated at a pinned Google root. False is a forgery. */
    val chainTrusted: Boolean = true,
    /** A serial in the chain is on the attestation CRL — a leaked keybox. */
    val keyboxRevoked: Boolean = false,
    /** One batch key seen across both StrongBox and TEE: impossible on genuine hardware. */
    val crossLevelReuse: Boolean = false,
    /** TEE-attested identity contradicts the self-reported `Build.*` values. */
    val devicePropMismatch: Boolean = false,
    /** Boot properties claim a clean boot the attestation denies. */
    val bootStateSpoofer: Boolean = false,
    // --- honest-but-weak facts: INTEGRITY / signals ------------------------------
    /** Leaf claims StrongBox but no StrongBox chain was presented. Fails closed. */
    val strongboxChainMissing: Boolean = false,
    /** The attestation EXPLICITLY reported securityLevel=Software — no hardware root. */
    val softwareAttested: Boolean = false,
    // --- attested platform facts, carried for the patch signals -----------------
    /** Attested framework patch, YYYYMM. Null when the tag was absent. */
    val osPatchLevel: Int? = null,
    /** Attested vendor patch, YYYYMMDD. */
    val vendorPatchLevel: Int? = null,
    /** Attested bootloader patch, YYYYMMDD. */
    val bootPatchLevel: Int? = null,
    /** The fingerprint recorded at bootstrap, carried for later scans. */
    val fingerprint: DeviceFingerprint? = null,
)
