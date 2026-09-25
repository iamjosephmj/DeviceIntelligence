package tech.thessemaj.deviceintelligence.verifier

/**
 * The evidence-extraction half of [ScanVerifier], split out so the verifier
 * file stays a readable gate/decision flow.
 *
 * Everything here is EXTRACTION + SYNTHESIS: parse a binding line, resolve an
 * opaque SIG code against the registry, correlate attestation facts, date
 * patch levels. None of it decides — every function either returns facts for
 * [ScanVerifier] to gate on, or resolved signals for the verdict's telemetry.
 * The only external effects are registry/policy lookups.
 *
 * Internal by design: the wire contract lives in ScanVerifier + SCHEMA.md.
 */
internal class ScanEvidence(
    private val registry: SignalRegistry,
    private val policy: Policy,
    private val licenses: LicenseRegistry,
    private val chainVerifier: ChainVerifier,
    /** Injected so patch staleness is testable without waiting for the calendar. */
    private val now: () -> Long,
) {
    /** See [EnrollVerifier.CrossLevel]. */
    internal data class CrossLevel(val reuse: Boolean, val strongboxChainMissing: Boolean)

    /** The `attestation` block, or null from a client too old to emit one. */
    @Suppress("UNCHECKED_CAST")
    fun attestationOf(doc: Map<String, Any?>): TokenAttestation? {
        val a = doc["attestation"] as? Map<String, Any?> ?: return null
        return TokenAttestation(
            level = AttestationLevel.parse(a["level"] as? String),
            signed = AttestationLevel.parse(a["signed"] as? String),
            reason = (a["reason"] as? String)?.takeIf { it.isNotEmpty() } ?: "UNKNOWN",
            detail = (a["detail"] as? String)?.takeIf { it.isNotEmpty() },
        )
    }

    /**
     * The SIG line's hex, empty when nothing signed this token.
     *
     * A degraded token still emits the `--BINDING` separator with an EMPTY SIG, so
     * that "no binding at all" stays reserved for a genuinely malformed token and
     * existing parsers keep their shape. The empty SIG is also AUTHORITATIVE over the
     * document's own `signed` claim: a device whose keystore died mid-call leaves a
     * document claiming a rung it never reached, and the binding is the fact.
     */
    fun bindingSig(binding: String): String {
        for (line in binding.split("\n")) if (line.startsWith("SIG$FS")) return line.substring(4)
        return ""
    }

    /**
     * Why this token is degraded, in the shared taxonomy. The gate in ScanVerifier is
     * the authority; these are the telemetry, and they are what makes a suppression
     * attempt VISIBLE instead of silent.
     */
    fun degradedSignals(a: TokenAttestation): List<ResolvedSignal> {
        val out = ArrayList<ResolvedSignal>()
        fun add(id: String, detail: String) = registry[id]?.let { m ->
            out.add(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                policy.isBlocking(m.id, m.severity)))
        }
        val detail = a.detail?.let { " ($it)" } ?: ""
        when (a.reason) {
            "NO_SESSION" -> add("INTEL_0023", "scan issued with no prepared session$detail")
            "LICENCE_EXPIRED", "LICENCE_PKG_MISMATCH", "LICENCE_UNPARSEABLE" ->
                add("INTEL_0038", "licence rejected at scan time: ${a.reason}$detail")
            else -> add("INTEL_0030", "attestation unavailable: ${a.reason}$detail")
        }
        if (a.signed == AttestationLevel.NONE) add("INTEL_0015", "token carries no signature")
        return out
    }

    /**
     * The cross-check, and the only reason the self-report is on the wire at all.
     *
     * `app` is what the device says about itself: app-visible, and whatever a patched
     * core wants it to be. On its own it proves nothing — an attacker simply reports a
     * licensed identity. What it CAN'T do is match a certificate it cannot forge, so
     * the DISAGREEMENT with the TEE-signed attested identity is the finding.
     *
     * Fail-open, like every other detector: a scan carrying no readable self-report,
     * or a session with no attested identity to compare against, emits nothing.
     * Absence of evidence is not evidence.
     */
    @Suppress("UNCHECKED_CAST")
    fun appSignals(doc: Map<String, Any?>, attested: AttestedApp?): List<ResolvedSignal> {
        if (attested == null) return emptyList()
        val app = doc["app"] as? Map<String, Any?> ?: return emptyList()
        val pkg = (app["package"] as? String)?.takeIf { it.isNotEmpty() } ?: return emptyList()
        val signer = (app["signer"] as? String)?.takeIf { it.isNotEmpty() } ?: return emptyList()

        fun sig(id: String, detail: String): List<ResolvedSignal> {
            val m = registry[id] ?: return emptyList()
            return listOf(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                policy.isBlocking(m.id, m.severity)))
        }

        val agrees = attested.packageNames.contains(pkg) &&
            attested.signatureDigests.any { it.equals(signer, ignoreCase = true) }
        if (!agrees) return sig("INTEL_0046",
            "reported=$pkg/${signer.take(16)}… attested=${attested.packageNames.firstOrNull() ?: "?"}")

        // Identity is genuine; the only remaining question is entitlement.
        if (!licenses.isLicensed(pkg, signer)) return sig("INTEL_0037", "package=$pkg")
        return emptyList()
    }

    /**
     * Surface the carried attestation findings as first-class registry SIGs, so a boot
     * spoof appears as INTEL_0055 in the signal list (the shared taxonomy) alongside the
     * gate that already rejects it. The gate is the authority; the SIG is the telemetry.
     */
    fun carriedSignals(s: ScanSession): List<ResolvedSignal> {
        val out = ArrayList<ResolvedSignal>()
        fun add(id: String, detail: String) = registry[id]?.let { m ->
            out.add(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                policy.isBlocking(m.id, m.severity)))
        }
        if (s.bootStateSpoofer) add("INTEL_0055", "self-report=green/locked but hardware attestation disagrees")
        if (s.crossLevelReuse) add("INTEL_0016", "same attestation batch key across StrongBox and TEE — leaked keybox")
        if (s.strongboxChainMissing) add("INTEL_0045", "StrongBox hardware indicated but no StrongBox attestation chain produced")
        if (s.softwareAttested) add("INTEL_0056", "attestation reports securityLevel=Software — no hardware root of trust")
        return out
    }

    @Suppress("UNCHECKED_CAST")
    fun fingerprintOf(doc: Map<String, Any?>): DeviceFingerprint? {
        val fp = doc["fp"] as? Map<String, Any?> ?: return null
        fun s(k: String) = (fp[k] as? String)?.takeIf { it.isNotEmpty() }
        return DeviceFingerprint(s("id"), s("aid"), s("lvl"),
            s("build"), s("kernel"), s("patch"), s("installer"))
    }

    /** YYYYMM or YYYYMMDD -> epoch seconds at the start of that month/day. */
    private fun patchToEpoch(v: Int): Long? = runCatching {
        val (y, m, d) = if (v > 999999) Triple(v / 10000, v / 100 % 100, v % 100)
                        else Triple(v / 100, v % 100, 1)
        if (m !in 1..12 || d !in 1..31) return null
        java.time.LocalDate.of(y, m, d).toEpochDay() * 86_400L
    }.getOrNull()

    /**
     * INTEL_0050 + INTEL_0019.
     *
     * Staleness uses the OLDEST of the three attested levels: a current framework
     * patch on a two-year-old bootloader is still exposed.
     *
     * The mismatch check compares ONLY the self-report against osPatchLevel, at
     * MONTH precision. Both are the framework patch — vendor and boot levels are the
     * SoC and bootloader patches and legitimately diverge on non-Pixel OEMs. And a
     * naive compare of 202604 against "2026-04-05" mismatches on every device on
     * earth; this registry has already retired two signals for false-positiving.
     */
    fun patchSignals(doc: Map<String, Any?>, s: ScanSession): List<ResolvedSignal> {
        val out = ArrayList<ResolvedSignal>()
        fun add(id: String, detail: String) = registry[id]?.let { m ->
            out.add(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                policy.isBlocking(m.id, m.severity)))
        }

        val epochs = listOfNotNull(s.osPatchLevel, s.vendorPatchLevel, s.bootPatchLevel)
            .mapNotNull { patchToEpoch(it) }
        if (epochs.isNotEmpty()) {
            val ageDays = (now() - epochs.min()) / 86_400L
            if (ageDays > policy.maxPatchAgeDays)
                add("INTEL_0050", "oldest attested patch is $ageDays days old " +
                    "(policy window ${policy.maxPatchAgeDays})")
        }

        val attestedMonth = s.osPatchLevel
        val reported = (s.fingerprint ?: fingerprintOf(doc))?.patch
        if (attestedMonth != null && reported != null) {
            // "2026-04-05" -> 202604. Fail open on anything unexpected.
            val reportedMonth = runCatching {
                reported.substring(0, 4).toInt() * 100 + reported.substring(5, 7).toInt()
            }.getOrNull()
            if (reportedMonth != null && reportedMonth != attestedMonth)
                add("INTEL_0019", "self-report $reported vs attested $attestedMonth")
        }
        return out
    }

    /**
     * Cross-level keybox forensics. [CrossLevel.reuse] is the strong, low-FP tell: the
     * SB and TEE chains were signed by the SAME batch key — genuine hardware provisions
     * distinct per-level batch keys, so one leaked keybox signing both proves injection.
     * [CrossLevel.strongboxChainMissing] is the fail-closed case: the leaf claims
     * StrongBox but no SB chain was produced, so `reuse` could not be evaluated.
     */
    fun crossLevelCheck(sbHex: List<String>, teeHex: List<String>, assurance: Assurance): CrossLevel {
        if (assurance == Assurance.STRONGBOX && sbHex.size < 2) return CrossLevel(false, true)
        if (sbHex.size < 2 || teeHex.size < 2) return CrossLevel(false, false)
        val sbBatch = chainVerifier.parseChain(sbHex)[1].publicKey.encoded
        val teeBatch = chainVerifier.parseChain(teeHex)[1].publicKey.encoded
        return CrossLevel(sbBatch.contentEquals(teeBatch), false)
    }

    /**
     * A human reason if any TEE-attested device property contradicts the self-reported
     * value, else null. Compared case-insensitively and only where BOTH are present:
     * absence is never a mismatch, so a device that does not attest its properties is
     * not flagged.
     */
    fun devicePropertyMismatch(attested: Map<String, String>, reported: Map<String, Any?>): String? {
        for ((k, a) in attested) {
            val r = (reported[k] as? String) ?: continue
            if (a.isNotBlank() && r.isNotBlank() && !a.equals(r, ignoreCase = true))
                return "attested $k='$a' != reported '$r'"
        }
        return null
    }

    fun isHex(s: String) = s.isNotEmpty() && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }

    private companion object {
        const val FS = "\u001F"
    }
}
