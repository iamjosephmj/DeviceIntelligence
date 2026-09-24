package tech.thessemaj.deviceintelligence.verifier

import java.security.cert.X509Certificate

class EnrollVerifier(
    private val sessionSigner: SessionSigner,
    pinnedRoots: List<X509Certificate> = PinnedRoots.default,
    private val crl: AttestationCrl = AttestationCrl.default,
    /**
     * Deployment-wide pin: the expected SHA-256 (hex) of the APK signing certificate,
     * checked against the OS/TEE-computed `signatureDigests` in the key-attestation
     * extension. Same configuration lifecycle as [pinnedRoots] — set once per
     * deployment, never per-request. Null (the default) is an explicit dev opt-out:
     * enrollment then records a carried "signer pin configured" check and relies on
     * the server attestation pin alone.
     */
    private val expectedSignerSha256: String? = null,
) {
    private val chainVerifier = ChainVerifier(pinnedRoots)

    fun enroll(bundleHex: String, issuedEnrollChallenge: String): EnrollResult {
        val checks = ArrayList<Check>()
        fun ck(n: String, ok: Boolean, d: String = "") = ok.also { checks.add(Check(n, ok, d, CheckKind.AUTH)) }

        val text = Keystream.decryptHex(bundleHex)
        val sep = text.indexOf(TokenDecoder.BINDING_SEP)
        if (!ck("binding present", sep >= 0)) return EnrollResult(false, null, checks, "unbound")
        val signed = text.substring(0, sep)
        val binding = text.substring(sep + TokenDecoder.BINDING_SEP.length)
        val doc = runCatching { Json.parseObject(signed) }.getOrDefault(emptyMap())
        if (!ck("signed content is JSON", doc.isNotEmpty())) return EnrollResult(false, null, checks, "bad json")

        ck("enroll challenge matches issued", (doc["enrollChallenge"] as? String) == issuedEnrollChallenge)

        // Parse CERT / XLEVEL_SB / XLEVEL_TEE lines.
        val certs = ArrayList<String>(); val sb = ArrayList<String>(); val tee = ArrayList<String>()
        for (line in binding.split("\n")) when {
            line.startsWith("CERT") -> certs.add(line.substring(5))
            line.startsWith("XLEVEL_SB") -> sb.add(line.substring(10))
            line.startsWith("XLEVEL_TEE") -> tee.add(line.substring(11))
        }
        if (!ck("chain present", certs.isNotEmpty())) return EnrollResult(false, null, checks, "no chain")

        val chain = runCatching { chainVerifier.parseChain(certs) }.getOrNull()
        if (chain == null || chain.isEmpty()) { ck("chain parses", false); return EnrollResult(false, null, checks, "chain parse") }
        val leaf = chain.first()

        // From here on, findings are CARRIED into the session and adjudicated at
        // challenge() — the per-request call the backend decides. enroll() issues a
        // session whenever a well-formed, FRESH attestation binding was produced (the TEE
        // call was made); it never rejects on an integrity/anti-spoof finding. That keeps
        // initialize() robust while the actual verdict (incl. keybox-injection / boot-state
        // spoof) lands at challenge.

        val chainTrusted = runCatching {
            val root = chainVerifier.verifyToPinnedRoot(chain)
            ck("chain -> pinned Google root", true, root.subjectX500Principal.name); true
        }.getOrElse { ck("chain -> pinned Google root", false, it.message ?: "chain error"); false }

        val attestFresh = runCatching {
            Hex.encode(Attestation.challenge(leaf)) == issuedEnrollChallenge.lowercase()
        }.getOrDefault(false)
        ck("attestation challenge == enroll challenge", attestFresh)

        // --- F2 (2026-09-10 spec): attested signer pin — the third hard-fail. ---
        // signatureDigests are computed by the OS/TEE at key creation from the APK's
        // signing certs; a re-signed artifact attests with the attacker's digest and
        // cannot forge ours. Missing/unparseable extension fails CLOSED when pinned.
        // Parsed once here and shared with the hard-fail return below.
        val attestedApp = runCatching { Attestation.attestedApp(leaf) }.getOrNull()
        val signerPinOk = expectedSignerSha256 == null ||
            attestedApp?.signatureDigests?.any {
                it.equals(expectedSignerSha256, ignoreCase = true)
            } == true
        if (expectedSignerSha256 == null) {
            ck("signer pin configured", true, "dev: unpinned — server attestation pin is the anchor")
        } else {
            ck("signer pin match", signerPinOk,
               if (signerPinOk) "" else "attested app digest set does not contain the pinned signer")
        }

        // --- attestation findings (recorded for telemetry; carried, NOT enroll-blocking) ---
        // NOTE: a leaf-notBefore-precedes-issuer "keybox injection" heuristic used to live
        // here (INTEL_0031, now retired). It false-positived on genuine StrongBox/TEE devices,
        // whose attestation leaf legitimately carries notBefore=epoch-0 while the issuer is
        // freshly minted per attestation. Keybox injection is covered instead by the CRL /
        // cross-level batch-key-reuse checks below and the boot-state buster (INTEL_0030).

        val fields = runCatching { Attestation.fields(leaf) }.getOrNull()
        val locked = fields?.deviceLocked == true
        // A missing/unparseable securityLevel grades to SOFTWARE, not TEE: absence of a
        // level is not evidence of hardware backing, and TokenVerifier's ">= TEE" gate is
        // only meaningful if SOFTWARE is actually reachable here.
        // INTEL_0044: securityLevel was EXPLICITLY reported as Software(0) — a real software
        // keystore, no hardware root of trust. Kept separate from `assurance` because the
        // null/unparseable case below also grades to SOFTWARE (fail-safe for the gate) but
        // proves nothing, and must not raise the signal.
        val softwareAttested = fields?.securityLevel == 0
        val assurance = when (fields?.securityLevel) {
            2 -> Assurance.STRONGBOX
            1 -> Assurance.TEE
            else -> Assurance.SOFTWARE
        }

        // Cross-level batch-key reuse (replayed keybox across StrongBox/TEE). Split into the
        // strong tell (same batch key across levels — INTEL_0032) and the fail-closed case
        // (StrongBox claimed but no SB chain — INTEL_0033, lower confidence).
        val xlevel = runCatching { crossLevelCheck(sb, tee, assurance) }.getOrDefault(CrossLevel(false, false))
        ck("no cross-level keybox reuse", !xlevel.reuse)
        ck("strongbox attestation chain present", !xlevel.strongboxChainMissing)

        // Keybox revocation (serial on the attestation CRL).
        val revokedSerial = runCatching {
            crl.firstRevoked(
                chain,
                if (sb.size >= 2) chainVerifier.parseChain(sb) else emptyList(),
                if (tee.size >= 2) chainVerifier.parseChain(tee) else emptyList(),
            )
        }.getOrNull()
        ck("no revoked keybox in chain", revokedSerial == null, revokedSerial?.let { "revoked serial $it" } ?: "")

        // Device-property honeypot: TEE-attested identity must match self-reported Build.*.
        @Suppress("UNCHECKED_CAST")
        val reported = (doc["device"] as? Map<String, Any?>).orEmpty()
        val attested = runCatching { Attestation.deviceProperties(leaf) }.getOrDefault(emptyMap())
        val propMismatch = devicePropertyMismatch(attested, reported)
        ck("device-property attestation matches self-report", propMismatch == null, propMismatch ?: "")

        // The device reports whether StrongBox HARDWARE is present
        // (PackageManager.FEATURE_STRONGBOX_KEYSTORE, `sbFeature`). Android throws the same
        // StrongBoxUnavailableException whether StrongBox is absent or merely failing right
        // now, so the exception alone cannot separate the two: a device that says it HAS the
        // hardware yet produced no StrongBox attestation hit a transient failure -> INTEL_0033.
        //
        // The capability interlock that used to live here (INTEL_0034) is RETIRED along with its
        // strongbox-devices.json device list — see the registry tombstone for what that costs.
        val sbFeature: Boolean? = when (reported["sbFeature"] as? String) {
            "1" -> true; "0" -> false; else -> null
        }
        val teeOnly = assurance != Assurance.STRONGBOX && sb.size < 2
        val strongboxTransient = teeOnly && sbFeature == true
        ck("StrongBox attestation available where hardware is present", !strongboxTransient,
           if (strongboxTransient) "device reports StrongBox hardware but produced no StrongBox attestation" else "")

        // Boot-state self-report vs hardware attestation — the consistent buster for any
        // prop-spoofing Play-Integrity-Fix (self-report claims green/locked while the TEE
        // attestation says otherwise). Signature-free (see [bootStateSpoofer]).
        val bootSpoofer = bootStateSpoofer(reported, fields)
        ck("boot-state self-report matches hardware attestation", !bootSpoofer,
           if (bootSpoofer) "self-report=green/locked but hardware attestation says boot=${fields?.bootStateName} locked=${fields?.deviceLocked}" else "")

        // enroll REJECTs only when it cannot establish a genuine, fresh binding: a replayed
        // enroll challenge, a stale attestation, a pinned-signer mismatch, or a malformed
        // attested key. Everything else is carried into the signed session for challenge()
        // to adjudicate.
        val enrollChallengeOk = (doc["enrollChallenge"] as? String) == issuedEnrollChallenge
        if (!enrollChallengeOk) return EnrollResult(false, null, checks, "enroll challenge mismatch")
        if (!attestFresh) return EnrollResult(false, null, checks, "attestation not fresh (challenge echo)")
        if (!signerPinOk) return EnrollResult(false, null, checks, "signer pin")
        val spki = doc["attestedKey"] as? String ?: Hex.encode(leaf.publicKey.encoded)
        if (!isHex(spki)) return EnrollResult(false, null, checks, "attestedKey not hex")

        val session = Session(
            pinnedKeySpkiHex = spki,
            assurance = assurance,
            bootState = fields?.bootStateName ?: "?",
            deviceLocked = locked,
            issuedAt = (doc["ts"] as? Long) ?: 0L,
            chainTrusted = chainTrusted,
            keyboxRevoked = revokedSerial != null,
            crossLevelReuse = xlevel.reuse,
            // Both routes to "StrongBox hardware exists but produced no StrongBox chain"
            // surface as INTEL_0033: the leaf claiming StrongBox without an SB chain, and a
            // reported-capable device that fell back to TEE.
            strongboxChainMissing = xlevel.strongboxChainMissing || strongboxTransient,
            devicePropMismatch = propMismatch != null,
            bootStateSpoofer = bootSpoofer,
            softwareAttested = softwareAttested,
        )
        return EnrollResult(true, sessionSigner.issue(session), checks, null)
    }

    companion object {
        /**
         * The consistent Play-Integrity-Fix buster: true when the device SELF-REPORTS a
         * clean/locked boot (ro.boot.verifiedbootstate=green + flash.locked=1 or
         * vbmeta.device_state=locked) while its hardware attestation RootOfTrust says
         * otherwise. A genuine locked device agrees in both; a plain unlocked device claims
         * neither. Only the contradiction — a spoofer forcing the props clean while the TEE
         * reports the truth — returns true. Signature-free; independent of PIF fingerprints.
         */
        fun bootStateSpoofer(reported: Map<String, Any?>, fields: AttestationFields?): Boolean {
            val vbs = (reported["vbs"] as? String)?.lowercase() ?: ""
            val flashLocked = (reported["blocked"] as? String) ?: ""
            val vbmeta = (reported["vbmeta"] as? String)?.lowercase() ?: ""
            // Any self-reported clean/locked indicator — verifiedbootstate=green OR flash.locked=1
            // OR vbmeta.device_state=locked. Broader than green-only: a prop-spoofer that forces the
            // lock props but leaves verifiedbootstate blank/other still contradicts the hardware.
            val selfClaimsClean = vbs == "green" || flashLocked == "1" || vbmeta == "locked"
            val attestClean = fields?.verifiedBootState == 0 && fields.deviceLocked == true
            // Fire only on a genuine contradiction: self-report claims clean/locked while the
            // hardware attestation does not. Genuine devices agree on both, so this stays FP-free.
            return selfClaimsClean && !attestClean
        }
    }

    /** Outcome of the cross-level keybox-reuse check (see [crossLevelCheck]). */
    data class CrossLevel(val reuse: Boolean, val strongboxChainMissing: Boolean)

    /**
     * Cross-level keybox forensics. [reuse] is the strong, low-FP tell: the SB and TEE
     * cross-level chains were signed by the SAME batch key — genuine hardware provisions
     * distinct per-level batch keys, so one leaked keybox signing both proves injection.
     * [strongboxChainMissing] is the fail-closed case: the leaf claims StrongBox but no SB
     * chain was produced, so [reuse] could not be evaluated — lower confidence, because a
     * transient StrongBox attestation failure on a genuine device can also cause it.
     */
    private fun crossLevelCheck(sbHex: List<String>, teeHex: List<String>, assurance: Assurance): CrossLevel {
        if (assurance == Assurance.STRONGBOX && sbHex.size < 2) return CrossLevel(false, true)
        if (sbHex.size < 2 || teeHex.size < 2) return CrossLevel(false, false)
        val sbBatch = chainVerifier.parseChain(sbHex)[1].publicKey.encoded
        val teeBatch = chainVerifier.parseChain(teeHex)[1].publicKey.encoded
        return CrossLevel(sbBatch.contentEquals(teeBatch), false)
    }

    /**
     * A human reason if any TEE-attested device property contradicts the self-reported
     * value (compared case-insensitively, only where BOTH are present), else null.
     * Absence is never a mismatch — fail-open, so a device that doesn't attest its
     * properties is not flagged.
     */
    private fun devicePropertyMismatch(attested: Map<String, String>, reported: Map<String, Any?>): String? {
        for ((k, a) in attested) {
            val r = (reported[k] as? String) ?: continue
            if (a.isNotBlank() && r.isNotBlank() && !a.equals(r, ignoreCase = true))
                return "attested $k='$a' != reported '$r'"
        }
        return null
    }

    private fun isHex(s: String): Boolean =
        s.isNotEmpty() && s.length % 2 == 0 && s.all { it in '0'..'9' || it in 'a'..'f' }
}
