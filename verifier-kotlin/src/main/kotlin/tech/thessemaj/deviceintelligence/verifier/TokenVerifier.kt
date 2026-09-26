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
        val checks = Checks()
        val t = TokenText(tokenHex)

        if (!checks.auth("binding present", t.hasBinding, if (!t.hasBinding) "unbound/legacy token" else "")) {
            return result(checks, t)
        }
        if (t.doc.isEmpty()) {
            checks.auth("signed content is JSON", false, "unparseable signed_content")
            return result(checks, t)
        }

        val tokenNonce = t.doc["nonce"] as? String ?: ""
        checks.auth("nonce matches issued", tokenNonce == issuedNonce, "token=${tokenNonce.take(16)}… issued=${issuedNonce.take(16)}…")

        val (sigHex, certsHex) = parseBinding(t.binding)
        if (!checks.auth("chain + signature present", sigHex.isNotEmpty() && certsHex.isNotEmpty())) {
            return result(checks, t)
        }

        val chain = runCatching { chainVerifier.parseChain(certsHex) }.getOrNull()
        if (chain == null || chain.isEmpty()) {
            checks.auth("chain parses", false, "could not parse cert chain")
            return result(checks, t)
        }
        val leaf = chain.first()

        runCatching { chainVerifier.verifyToPinnedRoot(chain) }
            .onSuccess { checks.auth("chain -> pinned Google root", true, it.subjectX500Principal.name) }
            .onFailure { checks.auth("chain -> pinned Google root", false, it.message ?: "chain error") }

        runCatching { Attestation.challenge(leaf) }
            .onSuccess { chal -> checks.auth("attestation challenge == nonce", Hex.encode(chal) == issuedNonce.lowercase(), "challenge=${Hex.encode(chal).take(16)}…") }
            .onFailure { checks.auth("attestation challenge == nonce", false, it.message ?: "no challenge") }

        runCatching {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(leaf.publicKey)
            sig.update(t.signed.toByteArray(Charsets.UTF_8))
            sig.verify(Hex.decode(sigHex))
        }.onSuccess { ok -> checks.auth("signature over verdict", ok, if (ok) "" else "ECDSA verify failed") }
            .onFailure { checks.auth("signature over verdict", false, it.message ?: "signature error") }

        // Device-integrity layer — the TEE's own attestation fields.
        runCatching { Attestation.fields(leaf) }
            .onSuccess { f ->
                checks.integ("hardware security level >= TEE", f.securityLevel == 1 || f.securityLevel == 2, f.securityLevelName)
                checks.integ("verified boot state = Verified", f.verifiedBootState == 0, f.bootStateName)
                checks.integ("device locked", f.deviceLocked == true, f.deviceLocked.toString())
            }
            .onFailure { checks.integ("attestation device-integrity fields", false, it.message ?: "parse error") }

        return result(checks, t)
    }

    fun verifyChallenge(tokenHex: String, issuedChallenge: String, sessionSigner: SessionSigner): VerificationResult {
        val checks = Checks()
        val t = TokenText(tokenHex)

        val session = (t.doc["sessionId"] as? String)?.let { sessionSigner.open(it) }
        if (!checks.auth("session valid", session != null, if (session == null) "sessionId forged/expired -> re-enroll" else "")) {
            return result(checks, t)
        }
        val tokenChallenge = t.doc["challenge"] as? String ?: ""
        checks.auth("challenge matches issued", tokenChallenge == issuedChallenge, "token=${tokenChallenge.take(12)}… issued=${issuedChallenge.take(12)}…")

        val (sigHex, _) = parseBinding(t.binding)
        if (!checks.auth("signature present", sigHex.isNotEmpty())) return result(checks, t)

        runCatching {
            val spki = java.security.spec.X509EncodedKeySpec(Hex.decode(session!!.pinnedKeySpkiHex))
            val pub = java.security.KeyFactory.getInstance("EC").generatePublic(spki)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pub); update(t.signed.toByteArray(Charsets.UTF_8)); verify(Hex.decode(sigHex))
            }
        }.onSuccess { ok -> checks.auth("signature by pinned key", ok, if (ok) "" else "ECDSA verify failed") }
            .onFailure { checks.auth("signature by pinned key", false, it.message ?: "sig error") }

        // All attestation validations run HERE, on the facts carried (HMAC-signed) from
        // enroll — enroll itself never rejects on them. Proven forgeries are AUTH failures
        // (-> REJECT: the attestation isn't genuine); honest-but-compromised device-integrity
        // facts are INTEGRITY failures (-> COMPROMISED). This is where the backend decides.
        session?.let {
            // Forgeries / active spoofers -> REJECT.
            checks.auth("attestation chain trusted", it.chainTrusted, if (it.chainTrusted) "" else "chain does not reach a pinned Google root")
            checks.auth("no revoked keybox", !it.keyboxRevoked)
            checks.auth("no cross-level keybox reuse", !it.crossLevelReuse)
            // strongboxChainMissing is NOT an auth REJECT: a genuine StrongBox device can hit a
            // transient StrongBox failure. It surfaces as INTEL_0045 (HIGH, observe-only; block via
            // policy if you want it hard). INTEL_0039 (capability interlock) is retired.
            checks.auth("device-property attestation matches self-report", !it.devicePropMismatch)
            checks.auth("boot-state self-report matches hardware attestation", !it.bootStateSpoofer,
                 if (it.bootStateSpoofer) "self-report claims clean/locked boot but attestation says otherwise — prop spoofer" else "")
            // Honest device-integrity facts -> COMPROMISED.
            // Real gate: SOFTWARE (which also covers a missing/unparseable securityLevel)
            // is not hardware-backed and fails. This was previously written as
            // `TEE || STRONGBOX` against a two-valued enum, i.e. always true.
            checks.integ("hardware security level >= TEE", it.assurance != Assurance.SOFTWARE, it.assurance.name)
            if (policy.requireStrongBox) checks.integ("StrongBox required by policy", it.assurance == Assurance.STRONGBOX, it.assurance.name)
            checks.integ("verified boot state = Verified", it.bootState == "Verified", it.bootState)
            checks.integ("device locked", it.deviceLocked, it.deviceLocked.toString())
        }
        return result(checks, t, attestationSignals(session), pointKey = "name", nonceKey = "challenge")
    }

    /** The [Session] forgeries surfaced as first-class registry signals, so a boot-state
     *  spoof appears as INTEL_0055 in the verdict's signal list alongside the auth gate
     *  that already REJECTs it. The gate is the authority; the SIG is the named telemetry. */
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

    /** The layered decision: REJECT unless authentic, COMPROMISED on any integrity
     *  failure or blocking signal, TRUSTWORTHY only when all three layers clear. */
    private fun result(
        checks: Checks,
        t: TokenText,
        extraSignals: List<ResolvedSignal> = emptyList(),
        pointKey: String = "point",
        nonceKey: String = "nonce",
    ): VerificationResult {
        val signals = Signals.resolve(t.doc, registry, policy) + extraSignals
        val decision = when {
            !checks.authentic -> Decision.REJECT
            checks.deviceIntegrityOk && signals.none { it.blocking } -> Decision.TRUSTWORTHY
            else -> Decision.COMPROMISED
        }
        return VerificationResult(
            decision = decision,
            authentic = checks.authentic,
            deviceIntegrityOk = checks.deviceIntegrityOk,
            checks = checks.toList(),
            schemaVersion = (t.doc["schemaVersion"] as? Long)?.toInt(),
            point = t.doc[pointKey] as? String,
            ts = t.doc["ts"] as? Long,
            nonce = t.doc[nonceKey] as? String,
            device = Signals.device(t.doc),
            signals = signals,
        )
    }

    private companion object {
        const val FS = ""

        /** SIG<FS>hex and one-or-more CERT<FS>hex lines out of the binding payload. */
        fun parseBinding(binding: String): Pair<String, List<String>> {
            var sigHex = ""
            val certsHex = ArrayList<String>()
            for (line in binding.split("\n")) {
                when {
                    line.startsWith("SIG$FS") -> sigHex = line.substring(4)
                    line.startsWith("CERT$FS") -> certsHex.add(line.substring(5))
                }
            }
            return sigHex to certsHex
        }
    }
}

/** The decrypted token split at the binding separator, with its parsed (untrusted)
 *  document. Shared preamble of both verify flows — [TokenDecoder.BINDING_SEP] is the
 *  only framing that matters below the envelope. */
private class TokenText(tokenHex: String) {
    private val text = Keystream.decryptHex(tokenHex)
    private val sepIdx = text.indexOf(TokenDecoder.BINDING_SEP)

    val hasBinding = sepIdx >= 0
    val signed = if (hasBinding) text.substring(0, sepIdx) else text
    val binding = if (hasBinding) text.substring(sepIdx + TokenDecoder.BINDING_SEP.length) else ""
    val doc: Map<String, Any?> = runCatching { Json.parseObject(signed) }.getOrDefault(emptyMap())
}

/** The check ledger. Each gate records one [Check] under its layer, and the two
 *  layer verdicts — authentic / deviceIntegrityOk — fall out of the ledger, so no
 *  consumer ever re-derives "which checks count for which layer" by hand. */
private class Checks {
    private val all = ArrayList<Check>()

    fun auth(name: String, ok: Boolean, detail: String = "") =
        ok.also { all.add(Check(name, ok, detail, CheckKind.AUTH)) }

    fun integ(name: String, ok: Boolean, detail: String = "") =
        ok.also { all.add(Check(name, ok, detail, CheckKind.INTEGRITY)) }

    val authentic get() = all.filter { it.kind == CheckKind.AUTH }.all { it.ok }
    val deviceIntegrityOk get() = all.filter { it.kind == CheckKind.INTEGRITY }.all { it.ok }
    fun toList(): List<Check> = all
}
