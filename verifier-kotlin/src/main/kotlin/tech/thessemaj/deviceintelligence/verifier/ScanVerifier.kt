package tech.thessemaj.deviceintelligence.verifier

import java.security.KeyFactory
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.PrivateKey
import java.security.spec.X509EncodedKeySpec

/**
 * The single backend entry point for scan tokens, replacing the EnrollVerifier /
 * TokenVerifier split.
 *
 * A scan is either a BOOTSTRAP (the first of a cold start: it carries a hardware
 * attestation chain bound to the session id) or STEADY-STATE (signed by the key
 * that bootstrap attested). Both arrive on the same call.
 *
 * Stateless by construction: a bootstrap scan RETURNS the attested key for the
 * caller to store on its own session record, and later scans take it back as
 * [boundKey]. Nothing per-device is kept here, so there is no store to size, expire
 * or rate-limit.
 *
 * Gates are deliberately few. Everything a detector found — boot state, assurance
 * level, keybox reuse, CRL status — is GRADED, not gated: the device is a signed
 * sensor and the verdict is the caller's policy decision, per request.
 *
 * (Evidence extraction — binding parsing, signal synthesis, attestation fact
 * correlation — lives in [ScanEvidence]; this file is the gate + decision flow.)
 */
class ScanVerifier(
    pinnedRoots: List<X509Certificate> = PinnedRoots.default,
    private val crl: AttestationCrl = AttestationCrl.default,
    private val registry: SignalRegistry = SignalRegistry.bundled,
    private val policy: Policy = Policy(),
    private val licenses: LicenseRegistry = OpenLicenseRegistry,
    /** Injected so patch staleness is testable without waiting for the calendar. */
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val chainVerifier = ChainVerifier(pinnedRoots)
    private val evidence = ScanEvidence(registry, policy, licenses, chainVerifier, now)

    /**
     * Verify a scan, loading the server key from [serverPriv] ourselves.
     *
     * PREFER THIS over the [PrivateKey] overload. That one forces the CALLER to
     * construct the key, and below API 33 `KeyFactory.getInstance("XDH")` throws —
     * so the library's own X25519 fallback was unreachable, because you could not
     * get to it without already holding a key you could not build. Taking the key
     * MATERIAL moves construction inside, where the fallback lives.
     *
     * Accepts PEM or raw DER PKCS#8; the stream is closed. Parsed keys are cached
     * on a digest of their bytes, so a backend calling this per request parses once.
     */
    fun verifyScan(
        token: String,
        issuedSessionId: String,
        serverPriv: java.io.InputStream,
        session: ScanSession? = null,
    ): ScanResult = verifyScan(token, issuedSessionId, serverKeyFrom(serverPriv), session)

    /** Exposed so callers that verify repeatedly can hold the parsed key themselves. */
    fun serverKeyFrom(source: java.io.InputStream): PrivateKey = ServerKey.from(source)

    /**
     * Verify a scan with an already-constructed key. Correct when the key comes from
     * somewhere PEM cannot express — an HSM, a platform keystore — but on Android
     * below API 33 the caller cannot build one at all; use the InputStream overload.
     */
    fun verifyScan(
        token: String,
        issuedSessionId: String,
        serverPriv: PrivateKey,
        session: ScanSession? = null,
    ): ScanResult {
        val checks = ArrayList<Check>()
        fun ck(n: String, ok: Boolean, d: String = "") =
            ok.also { checks.add(Check(n, ok, d, CheckKind.AUTH)) }
        // Early rejections carry their SIGNALS. A rejected token is still telemetry —
        // "this device claims X and cannot prove it" is exactly what the backend most
        // wants to see, and returning an empty list here blinded it to those cases.
        fun fail(
            reason: String,
            bootstrap: Boolean = false,
            signals: List<ResolvedSignal> = emptyList(),
            attestation: TokenAttestation? = null,
            session: ScanSession? = null,
        ) = ScanResult(false, bootstrap, false, session, checks, signals, reason,
            attestation = attestation)

        // The scan path is v2-only. A v1 token here is a downgrade attempt or a stale
        // client; either way it must not be accepted on the strength of a baked key.
        if (!ck("v2 envelope", TokenCryptoV2.isV2(token))) return fail("not a v2 token")

        val text = runCatching { String(TokenCryptoV2.decrypt(token, serverPriv)) }.getOrNull()
        if (!ck("envelope opens", text != null)) return fail("envelope did not open")

        val sep = text!!.indexOf(TokenDecoder.BINDING_SEP)
        if (!ck("binding present", sep >= 0)) return fail("unbound")
        val signed = text.substring(0, sep)
        val binding = text.substring(sep + TokenDecoder.BINDING_SEP.length)

        val doc = runCatching { Json.parseObject(signed) }.getOrDefault(emptyMap())
        if (!ck("signed content is JSON", doc.isNotEmpty())) return fail("bad json")

        val bootstrap = doc["bootstrap"] == true
        val attestation = evidence.attestationOf(doc)
        val signals = Signals.resolve(doc, registry, policy)

        // Recorded, but not yet returned on: a degraded token often carries no session
        // id at all, so the mismatch is a SYMPTOM of the degradation. Reporting it as
        // the reason would bury the real story and skip the degradation signals.
        val sessionIdOk = ck("session id matches issued", (doc["sessionId"] as? String) == issuedSessionId)

        // A DEGRADED token — one the device could not bind to a hardware key — is
        // unauthenticated by construction: anyone able to encrypt to the server public
        // key can mint one naming any session. It is therefore never `ok`, and never
        // establishes or replaces session facts. What it DOES do is arrive with its
        // evidence, which is the whole reason it is emitted instead of suppressed.
        //
        // Containment: an established session is returned untouched. Degraded tokens
        // are cheap to forge, so if one could revoke the session it names, an attacker
        // could lock out other users by minting them against observed session ids —
        // trading a signal-suppression bug for a denial-of-service one. The decision
        // stays anchored to the strongest evidence the session has seen.
        val sigHex = evidence.bindingSig(binding)
        if (attestation != null && (attestation.degraded || sigHex.isEmpty())) {
            ck("token carries a hardware-attested binding", false,
               "${attestation.reason} (signed=${attestation.signed})")
            // The device reports its own degradation too. Synthesis is the FALLBACK,
            // for a client that predates those codes — so drop anything already there
            // rather than reporting the same finding twice.
            val already = signals.map { it.id }.toSet()
            return fail("unattested: ${attestation.reason}", bootstrap,
                signals + evidence.degradedSignals(attestation).filter { it.id !in already },
                attestation, session)
        }

        if (!sessionIdOk) return fail("session id mismatch", bootstrap, signals, attestation)

        return if (bootstrap)
            verifyBootstrap(doc, binding, issuedSessionId, signed, checks, signals, attestation)
        else verifySteadyState(doc, binding, signed, session, checks, signals, attestation)
    }

    /**
     * First scan of a cold start: the only one that carries an attestation, and
     * therefore the only chance to establish what kind of device this is.
     *
     * The hard gates are narrow — a genuine, fresh, chain-verified attestation. Every
     * other finding (boot state, lock, assurance, keybox revocation, cross-level
     * reuse, property honeypot, boot-state spoofer) is COMPUTED here and carried in
     * the returned [ScanSession], then adjudicated on this and every later scan. That
     * split is deliberate: attestation runs once, so the facts must outlive it.
     */
    private fun verifyBootstrap(
        doc: Map<String, Any?>,
        binding: String,
        issuedSessionId: String,
        signed: String,
        checks: ArrayList<Check>,
        signals: List<ResolvedSignal>,
        attestation: TokenAttestation?,
    ): ScanResult {
        fun ck(n: String, ok: Boolean, d: String = "") =
            ok.also { checks.add(Check(n, ok, d, CheckKind.AUTH)) }
        fun fail(reason: String) =
            ScanResult(false, true, false, null, checks, signals, reason, attestation = attestation)

        // Parse the binding: leaf chain plus the cross-level chains used for the
        // leaked-keybox forensics.
        val certs = ArrayList<String>(); val sb = ArrayList<String>(); val tee = ArrayList<String>()
        for (line in binding.split("\n")) when {
            line.startsWith("CERT") -> certs.add(line.substring(5))
            line.startsWith("XLEVEL_SB") -> sb.add(line.substring(10))
            line.startsWith("XLEVEL_TEE") -> tee.add(line.substring(11))
        }
        if (!ck("chain present", certs.isNotEmpty())) return fail("no chain")

        val chain = runCatching { chainVerifier.parseChain(certs) }.getOrNull()
        if (chain.isNullOrEmpty()) { ck("chain parses", false); return fail("chain parse") }
        val leaf = chain.first()

        val chainTrusted = runCatching {
            val root = chainVerifier.verifyToPinnedRoot(chain)
            ck("chain -> pinned Google root", true, root.subjectX500Principal.name); true
        }.getOrElse { ck("chain -> pinned Google root", false, it.message ?: "chain error"); false }
        if (!chainTrusted) return fail("chain does not reach a pinned Google root")

        // Freshness. The attestation challenge is the raw session-id bytes, so a
        // captured bootstrap scan is useless against any other session.
        val challengeOk = runCatching {
            Attestation.challenge(leaf).contentEquals(issuedSessionId.toByteArray(Charsets.UTF_8))
        }.getOrDefault(false)
        if (!ck("attestation challenge == session id", challengeOk))
            return fail("attestation not bound to this session")

        val spki = doc["attestedKey"] as? String
        if (!ck("attested key present and hex", spki != null && evidence.isHex(spki)))
            return fail("attestedKey missing or not hex")

        // ---- device-integrity facts: computed here, CARRIED, adjudicated below ----
        val fields = runCatching { Attestation.fields(leaf) }.getOrNull()
        val platform = runCatching { Attestation.attestedPlatform(leaf) }
            .getOrDefault(AttestedPlatform(null, null, null, null))
        val assurance = when (fields?.securityLevel) {
            2 -> Assurance.STRONGBOX
            1 -> Assurance.TEE
            // A missing or unparseable level grades to SOFTWARE so the gate fails safe;
            // only an EXPLICIT Software(0) raises INTEL_0056, since absence of evidence is
            // not evidence of a software keystore.
            else -> Assurance.SOFTWARE
        }
        val softwareAttested = fields?.securityLevel == 0

        val xlevel = runCatching { evidence.crossLevelCheck(sb, tee, assurance) }
            .getOrDefault(ScanEvidence.CrossLevel(false, false))

        val revokedSerial = runCatching {
            crl.firstRevoked(
                chain,
                if (sb.size >= 2) chainVerifier.parseChain(sb) else emptyList(),
                if (tee.size >= 2) chainVerifier.parseChain(tee) else emptyList(),
            )
        }.getOrNull()

        @Suppress("UNCHECKED_CAST")
        val reported = (doc["device"] as? Map<String, Any?>).orEmpty()
        val attestedProps = runCatching { Attestation.deviceProperties(leaf) }.getOrDefault(emptyMap())
        val propMismatch = evidence.devicePropertyMismatch(attestedProps, reported)
        val bootSpoofer = EnrollVerifier.bootStateSpoofer(reported, fields)

        // A device that says it HAS StrongBox hardware but produced no StrongBox chain
        // hit a transient failure -> INTEL_0045, same as the leaf claiming StrongBox
        // without one.
        val sbFeature: Boolean? = when (reported["sbFeature"] as? String) {
            "1" -> true; "0" -> false; else -> null
        }
        val strongboxTransient = assurance != Assurance.STRONGBOX && sb.size < 2 && sbFeature == true

        val session = ScanSession(
            attestedKey = spki!!,
            attestedApp = runCatching { Attestation.attestedApp(leaf) }.getOrNull(),
            assurance = assurance,
            bootState = fields?.bootStateName ?: "?",
            deviceLocked = fields?.deviceLocked == true,
            chainTrusted = true,
            keyboxRevoked = revokedSerial != null,
            crossLevelReuse = xlevel.reuse,
            devicePropMismatch = propMismatch != null,
            bootStateSpoofer = bootSpoofer,
            strongboxChainMissing = xlevel.strongboxChainMissing || strongboxTransient,
            softwareAttested = softwareAttested,
            osPatchLevel = platform.osPatchLevel,
            vendorPatchLevel = platform.vendorPatchLevel,
            bootPatchLevel = platform.bootPatchLevel,
            fingerprint = evidence.fingerprintOf(doc),
        )
        return adjudicate(doc, session, checks, signals, revokedSerial, propMismatch, true, attestation)
    }

    /**
     * Every later scan. No attestation runs, so trust comes from two places: the
     * signature by the key bootstrap attested, and the device-integrity facts the
     * caller carried forward in [session].
     */
    private fun verifySteadyState(
        doc: Map<String, Any?>,
        binding: String,
        signed: String,
        session: ScanSession?,
        checks: ArrayList<Check>,
        signals: List<ResolvedSignal>,
        attestation: TokenAttestation?,
    ): ScanResult {
        fun ck(n: String, ok: Boolean, d: String = "") =
            ok.also { checks.add(Check(n, ok, d, CheckKind.AUTH)) }

        // Signals are reported even when a gate fails. A rejected token is still
        // telemetry — "this device claims X and cannot prove it" is worth seeing, and
        // dropping it would blind the backend to exactly the cases it most wants.
        val all = signals + evidence.appSignals(doc, session?.attestedApp) +
            (session?.let { evidence.carriedSignals(it) } ?: emptyList())
        fun fail(reason: String) =
            ScanResult(false, false, false, null, checks, all, reason, attestation = attestation)

        // A steady-state scan with nothing to verify against is not "unverified" — it
        // is a caller bug (the bootstrap session was never stored) and must not pass.
        if (session == null) { ck("session carried from bootstrap", false); return fail("no bound key for session") }
        ck("session carried from bootstrap", true)

        val sigHex = evidence.bindingSig(binding)
        if (!ck("signature present", sigHex.isNotEmpty())) return fail("no signature")

        val verified = runCatching {
            val pub = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(Hex.decode(session.attestedKey)))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pub); update(signed.toByteArray(Charsets.UTF_8)); verify(Hex.decode(sigHex))
            }
        }.getOrDefault(false)
        if (!ck("signature by the bound key", verified, if (verified) "" else "ECDSA verify failed"))
            return fail("signature does not verify")

        return adjudicate(doc, session, checks, signals, null, null, false, attestation)
    }

    /**
     * The verdict, applied identically to every scan from the carried facts.
     *
     * AUTH failures are proven FORGERIES — a chain that does not reach a pinned root,
     * a revoked keybox, one keybox signing both security levels, attested properties
     * contradicting the self-report, or props claiming a clean boot the TEE denies.
     * They mean the attestation is not genuine, so nothing in the token can be
     * trusted: REJECT.
     *
     * INTEGRITY failures are HONEST reports of an untrustworthy device — no hardware
     * backing, an unverified boot, an unlocked bootloader. The token is real; the
     * device is not to be trusted: COMPROMISED.
     *
     * Keeping them apart is the whole point: "you are lying to me" and "you are
     * telling me something bad" warrant different responses.
     */
    private fun adjudicate(
        doc: Map<String, Any?>,
        session: ScanSession,
        checks: ArrayList<Check>,
        signals: List<ResolvedSignal>,
        revokedSerial: String?,
        propMismatch: String?,
        bootstrap: Boolean,
        attestation: TokenAttestation?,
    ): ScanResult {
        fun auth(n: String, ok: Boolean, d: String = "") = checks.add(Check(n, ok, d, CheckKind.AUTH))
        fun integ(n: String, ok: Boolean, d: String = "") = checks.add(Check(n, ok, d, CheckKind.INTEGRITY))

        // Proven forgeries -> REJECT.
        auth("attestation chain trusted", session.chainTrusted,
             if (session.chainTrusted) "" else "chain does not reach a pinned Google root")
        auth("no revoked keybox", !session.keyboxRevoked, revokedSerial?.let { "revoked serial $it" } ?: "")
        auth("no cross-level keybox reuse", !session.crossLevelReuse,
             if (session.crossLevelReuse) "same batch key across StrongBox and TEE — leaked keybox" else "")
        auth("device-property attestation matches self-report", !session.devicePropMismatch, propMismatch ?: "")
        auth("boot-state self-report matches hardware attestation", !session.bootStateSpoofer,
             if (session.bootStateSpoofer)
                 "self-report claims clean/locked boot but attestation says otherwise — prop spoofer" else "")

        // Honest device-integrity facts -> COMPROMISED.
        integ("hardware security level >= TEE", session.assurance != Assurance.SOFTWARE, session.assurance.name)
        if (policy.requireStrongBox)
            integ("StrongBox required by policy", session.assurance == Assurance.STRONGBOX, session.assurance.name)
        integ("verified boot state = Verified", session.bootState == "Verified", session.bootState)
        integ("device locked", session.deviceLocked, session.deviceLocked.toString())

        // StrongBox-chain-missing is NOT a gate: a genuine StrongBox device can hit a
        // transient failure. It surfaces as INTEL_0045 for policy to weigh.
        val all = signals + evidence.appSignals(doc, session.attestedApp) + evidence.carriedSignals(session) +
            evidence.patchSignals(doc, session)
        val ok = checks.filter { it.kind == CheckKind.AUTH }.all { it.ok }
        val integrityOk = checks.filter { it.kind == CheckKind.INTEGRITY }.all { it.ok }
        val reason = checks.firstOrNull { it.kind == CheckKind.AUTH && !it.ok }?.name

        return ScanResult(ok, bootstrap, integrityOk, if (bootstrap) session else null,
            checks, all, reason, session.fingerprint ?: evidence.fingerprintOf(doc), attestation)
    }
}
