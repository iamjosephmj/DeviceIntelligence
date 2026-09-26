package tech.thessemaj.deviceintelligence.verifier

import java.security.Signature
import java.security.cert.X509Certificate

/**
 * The backend entry point: turn a token + the nonce the server issued into a
 * trust [Decision]. Kotlin port of tools/server/verify_token.py.
 *
 * ```
 * val result = TokenVerifier().verify(tokenHex, issuedNonce)
 * when (result.decision) {
 *     Decision.TRUSTWORTHY -> allow()
 *     Decision.COMPROMISED -> stepUp(result.blockingSignals)
 *     Decision.REJECT      -> deny()   // not a genuine, fresh binding
 * }
 * ```
 *
 * The decision is LAYERED and mirrors the Python exactly:
 *  - authenticity — binding present · nonce fresh · challenge == nonce ·
 *    chain → pinned Google root · ECDSA signature valid. Fail any ⇒ REJECT.
 *  - device integrity — the TEE's own attestation: security level ≥ TEE,
 *    verifiedBootState == Verified, deviceLocked.
 *  - policy over signals — each resolved code run through [Policy].
 *
 * `decision = authentic AND deviceIntegrityOk AND no blocking signal`.
 */
class TokenVerifier(
    private val registry: SignalRegistry = SignalRegistry.bundled,
    private val policy: Policy = Policy(),
    pinnedRoots: List<X509Certificate> = PinnedRoots.default,
) {
    private val chainVerifier = ChainVerifier(pinnedRoots)

    fun verify(tokenHex: String, issuedNonce: String): VerificationResult {
        val checks = ArrayList<Check>()
        fun auth(name: String, ok: Boolean, detail: String = "") = ok.also { checks.add(Check(name, ok, detail, CheckKind.AUTH)) }
        fun integ(name: String, ok: Boolean, detail: String = "") = ok.also { checks.add(Check(name, ok, detail, CheckKind.INTEGRITY)) }

        val text = Keystream.decryptHex(tokenHex)
        val sepIdx = text.indexOf(TokenDecoder.BINDING_SEP)
        val signed = if (sepIdx >= 0) text.substring(0, sepIdx) else text
        val binding = if (sepIdx >= 0) text.substring(sepIdx + TokenDecoder.BINDING_SEP.length) else ""

        // Parse the document up front so we can always surface the (untrusted) signals.
        val doc: Map<String, Any?> = runCatching { Json.parseObject(signed) }.getOrDefault(emptyMap())

        if (!auth("binding present", sepIdx >= 0, if (sepIdx < 0) "unbound/legacy token" else "")) {
            return result(checks, doc)
        }
        if (doc.isEmpty()) {
            auth("signed content is JSON", false, "unparseable signed_content")
            return result(checks, doc)
        }

        val tokenNonce = doc["nonce"] as? String ?: ""
        auth("nonce matches issued", tokenNonce == issuedNonce, "token=${tokenNonce.take(16)}… issued=${issuedNonce.take(16)}…")

        // Parse binding: SIG<FS>hex and one-or-more CERT<FS>hex lines.
        var sigHex = ""
        val certsHex = ArrayList<String>()
        for (line in binding.split("\n")) {
            when {
                line.startsWith("SIG$FS") -> sigHex = line.substring(4)
                line.startsWith("CERT$FS") -> certsHex.add(line.substring(5))
            }
        }
        if (!auth("chain + signature present", sigHex.isNotEmpty() && certsHex.isNotEmpty())) {
            return result(checks, doc)
        }

        val chain = runCatching { chainVerifier.parseChain(certsHex) }.getOrNull()
        if (chain == null || chain.isEmpty()) {
            auth("chain parses", false, "could not parse cert chain")
            return result(checks, doc)
        }
        val leaf = chain.first()

        runCatching { chainVerifier.verifyToPinnedRoot(chain) }
            .onSuccess { auth("chain -> pinned Google root", true, it.subjectX500Principal.name) }
            .onFailure { auth("chain -> pinned Google root", false, it.message ?: "chain error") }

        runCatching { Attestation.challenge(leaf) }
            .onSuccess { chal -> auth("attestation challenge == nonce", Hex.encode(chal) == issuedNonce.lowercase(), "challenge=${Hex.encode(chal).take(16)}…") }
            .onFailure { auth("attestation challenge == nonce", false, it.message ?: "no challenge") }

        runCatching {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(leaf.publicKey)
            sig.update(signed.toByteArray(Charsets.UTF_8))
            sig.verify(Hex.decode(sigHex))
        }.onSuccess { ok -> auth("signature over verdict", ok, if (ok) "" else "ECDSA verify failed") }
            .onFailure { auth("signature over verdict", false, it.message ?: "signature error") }

        // Device-integrity layer — the TEE's own attestation fields.
        runCatching { Attestation.fields(leaf) }
            .onSuccess { f ->
                integ("hardware security level >= TEE", f.securityLevel == 1 || f.securityLevel == 2, f.securityLevelName)
                integ("verified boot state = Verified", f.verifiedBootState == 0, f.bootStateName)
                integ("device locked", f.deviceLocked == true, f.deviceLocked.toString())
            }
            .onFailure { integ("attestation device-integrity fields", false, it.message ?: "parse error") }

        return result(checks, doc)
    }

    private fun result(checks: List<Check>, doc: Map<String, Any?>): VerificationResult {
        val authentic = checks.filter { it.kind == CheckKind.AUTH }.all { it.ok }
        val deviceOk = checks.filter { it.kind == CheckKind.INTEGRITY }.all { it.ok }
        val signals = Signals.resolve(doc, registry, policy)
        val blocking = signals.any { it.blocking }
        val decision = when {
            !authentic -> Decision.REJECT
            deviceOk && !blocking -> Decision.TRUSTWORTHY
            else -> Decision.COMPROMISED
        }
        return VerificationResult(
            decision = decision,
            authentic = authentic,
            deviceIntegrityOk = deviceOk,
            checks = checks,
            schemaVersion = (doc["schemaVersion"] as? Long)?.toInt(),
            point = doc["point"] as? String,
            ts = doc["ts"] as? Long,
            nonce = doc["nonce"] as? String,
            device = Signals.device(doc),
            signals = signals,
        )
    }

    fun verifyChallenge(tokenHex: String, issuedChallenge: String, sessionSigner: SessionSigner): VerificationResult {
        val checks = ArrayList<Check>()
        fun auth(n: String, ok: Boolean, d: String = "") = ok.also { checks.add(Check(n, ok, d, CheckKind.AUTH)) }
        fun integ(n: String, ok: Boolean, d: String = "") = ok.also { checks.add(Check(n, ok, d, CheckKind.INTEGRITY)) }

        val text = Keystream.decryptHex(tokenHex)
        val sepIdx = text.indexOf(TokenDecoder.BINDING_SEP)
        val signed = if (sepIdx >= 0) text.substring(0, sepIdx) else text
        val binding = if (sepIdx >= 0) text.substring(sepIdx + TokenDecoder.BINDING_SEP.length) else ""
        val doc: Map<String, Any?> = runCatching { Json.parseObject(signed) }.getOrDefault(emptyMap())

        val session = (doc["sessionId"] as? String)?.let { sessionSigner.open(it) }
        if (!auth("session valid", session != null, if (session == null) "sessionId forged/expired -> re-enroll" else "")) {
            return challengeResult(checks, doc, null)
        }
        val tokenChallenge = doc["challenge"] as? String ?: ""
        auth("challenge matches issued", tokenChallenge == issuedChallenge, "token=${tokenChallenge.take(12)}… issued=${issuedChallenge.take(12)}…")

        var sigHex = ""
        for (line in binding.split("\n")) if (line.startsWith("SIG$FS")) sigHex = line.substring(4)
        if (!auth("signature present", sigHex.isNotEmpty())) return challengeResult(checks, doc, session)

        runCatching {
            val spki = java.security.spec.X509EncodedKeySpec(Hex.decode(session!!.pinnedKeySpkiHex))
            val pub = java.security.KeyFactory.getInstance("EC").generatePublic(spki)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pub); update(signed.toByteArray(Charsets.UTF_8)); verify(Hex.decode(sigHex))
            }
        }.onSuccess { ok -> auth("signature by pinned key", ok, if (ok) "" else "ECDSA verify failed") }
            .onFailure { auth("signature by pinned key", false, it.message ?: "sig error") }

        // All attestation validations run HERE, on the facts carried (HMAC-signed) from
        // enroll — enroll itself never rejects on them. Proven forgeries are AUTH failures
        // (-> REJECT: the attestation isn't genuine); honest-but-compromised device-integrity
        // facts are INTEGRITY failures (-> COMPROMISED). This is where the backend decides.
        session?.let {
            // Forgeries / active spoofers -> REJECT.
            auth("attestation chain trusted", it.chainTrusted, if (it.chainTrusted) "" else "chain does not reach a pinned Google root")
            auth("no revoked keybox", !it.keyboxRevoked)
            auth("no cross-level keybox reuse", !it.crossLevelReuse)
            // strongboxChainMissing is NOT an auth REJECT: a genuine StrongBox device can hit a
            // transient StrongBox failure. It surfaces as INTEL_0045 (HIGH, observe-only; block via
            // policy if you want it hard). INTEL_0039 (capability interlock) is retired.
            auth("device-property attestation matches self-report", !it.devicePropMismatch)
            auth("boot-state self-report matches hardware attestation", !it.bootStateSpoofer,
                 if (it.bootStateSpoofer) "self-report claims clean/locked boot but attestation says otherwise — prop spoofer" else "")
            // Honest device-integrity facts -> COMPROMISED.
            // Real gate: SOFTWARE (which also covers a missing/unparseable securityLevel)
            // is not hardware-backed and fails. This was previously written as
            // `TEE || STRONGBOX` against a two-valued enum, i.e. always true.
            integ("hardware security level >= TEE", it.assurance != Assurance.SOFTWARE, it.assurance.name)
            if (policy.requireStrongBox) integ("StrongBox required by policy", it.assurance == Assurance.STRONGBOX, it.assurance.name)
            integ("verified boot state = Verified", it.bootState == "Verified", it.bootState)
            integ("device locked", it.deviceLocked, it.deviceLocked.toString())
        }
        return challengeResult(checks, doc, session)
    }

    private fun challengeResult(checks: List<Check>, doc: Map<String, Any?>, session: Session?): VerificationResult {
        val authentic = checks.filter { it.kind == CheckKind.AUTH }.all { it.ok }
        val deviceOk = checks.filter { it.kind == CheckKind.INTEGRITY }.all { it.ok }
        val signals = Signals.resolve(doc, registry, policy) + attestationSignals(session)
        val decision = when {
            !authentic -> Decision.REJECT
            deviceOk && signals.none { it.blocking } -> Decision.TRUSTWORTHY
            else -> Decision.COMPROMISED
        }
        return VerificationResult(decision, authentic, deviceOk, checks,
            (doc["schemaVersion"] as? Long)?.toInt(), doc["name"] as? String,
            doc["ts"] as? Long, doc["challenge"] as? String, Signals.device(doc), signals)
    }

    /**
     * Surface the carried attestation forgeries as first-class registry SIGs, so a
     * boot-state spoof appears as INTEL_0055 in the
     * verdict's signal list (the shared taxonomy), alongside the auth() gate that
     * already REJECTs it. The gate is the authority; the SIG is the named telemetry.
     */
    private fun attestationSignals(session: Session?): List<ResolvedSignal> {
        if (session == null) return emptyList()
        val out = ArrayList<ResolvedSignal>()
        fun add(id: String, detail: String) = registry[id]?.let { m ->
            out.add(ResolvedSignal(m.id, m.detector, m.kind, m.title, m.severity, detail,
                policy.isBlocking(m.id, m.severity)))
        }
        if (session.bootStateSpoofer) add("INTEL_0055", "self-report=green/locked but hardware attestation disagrees")
        if (session.crossLevelReuse) add("INTEL_0016", "same attestation batch key across StrongBox and TEE — leaked keybox")
        if (session.strongboxChainMissing) add("INTEL_0045", "StrongBox hardware indicated but no StrongBox attestation chain produced (fail-closed)")
        if (session.softwareAttested) add("INTEL_0056", "attestation reports securityLevel=Software — no hardware root of trust")
        return out
    }

    private companion object {
        const val FS = "\u001F"
    }
}
