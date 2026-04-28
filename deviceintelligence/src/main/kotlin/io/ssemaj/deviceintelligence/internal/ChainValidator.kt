package io.ssemaj.deviceintelligence.internal

import java.security.cert.X509Certificate

/**
 * Pure structural / freshness / consistency checks over an attested
 * X.509 chain plus its parsed [KeyDescription][ParsedKeyDescription]
 * extension.
 *
 * Used by [BootloaderIntegrityDetector] (F15) to surface specific,
 * stable subreason codes when the chain looks tampered — e.g. cached
 * (Tricky Store style replay), forged structurally, or internally
 * inconsistent with the device state the TEE itself claims.
 *
 * Every function:
 *  - is pure (no Android, no I/O, no global state); takes everything
 *    it needs as arguments
 *  - returns `null` on pass, or a stable lowercase snake_case
 *    subreason string on trip
 *  - is defensive: if the input is missing the data the check needs,
 *    the function returns `null` (defer) rather than tripping on
 *    something it can't actually verify
 *
 * The stable subreason vocabulary is the wire contract that backends
 * key on, so every code added here is documented in the README under
 * F15.
 *
 * **A note on KeyMint leaf-cert quirks.** Real Android KeyMint
 * implementations populate the attestation leaf cert with intentionally
 * non-meaningful values for certain X.509 fields, because the TEE
 * cannot rely on a wall-clock at keygen time:
 *
 *  - `notBefore = 1970-01-01`, `notAfter = 2048-01-01` (fixed defaults
 *    unless the caller passes [android.security.keystore.KeyGenParameterSpec.Builder.setKeyValidityStart]
 *    / `setKeyValidityEnd`, which we deliberately do NOT — we want the
 *    standard chain shape).
 *  - `serialNumber = 1` for every attestation cert (hardcoded in AOSP
 *    `keystore2` / KeyMint).
 *
 * Any check that compares the leaf's `notBefore`/`notAfter`/`serial`
 * to anything time- or uniqueness-meaningful would false-positive on
 * every real device. The validators below sidestep these fields and
 * derive freshness signals from data the TEE *does* sign meaningfully:
 * the embedded attestation challenge and the SubjectPublicKey.
 */
internal object ChainValidator {

    // ---- structural --------------------------------------------------------

    /**
     * The chain must have at least two certs (leaf + issuer). A
     * single-cert "chain" cannot be hardware attestation because the
     * leaf in real attestation is always signed by an intermediate.
     */
    fun validateStructure(chain: List<X509Certificate>): String? {
        if (chain.isEmpty()) return "chain_empty"
        if (chain.size < 2) return "chain_too_short"
        return null
    }

    /**
     * Each cert in `chain[0..n-2]` must be signed by `chain[i+1]`'s
     * public key. The root (last cert) must be self-signed.
     *
     * Note: this verifies the *links* in the chain, not that the
     * root is Google's known attestation root. Pinning the root
     * pubkey requires a current denylist + revocation set and is
     * intentionally a backend responsibility.
     */
    fun verifyChainSignatures(chain: List<X509Certificate>): String? {
        if (chain.isEmpty()) return "chain_empty"
        for (i in 0 until chain.size - 1) {
            try {
                chain[i].verify(chain[i + 1].publicKey)
            } catch (t: Throwable) {
                return "chain_signature_invalid"
            }
        }
        val root = chain.last()
        try {
            root.verify(root.publicKey)
        } catch (t: Throwable) {
            return "chain_root_not_self_signed"
        }
        return null
    }

    /**
     * Validity periods on the *issuer side* of the chain (chain[1]
     * onwards) must be properly nested: each issuer's window must
     * lie inside its own issuer's window.
     *
     * **Skips the leaf-vs-chain[1] comparison** because real KeyMint
     * leaves use fixed `1970..2048` defaults that always outlast any
     * real intermediate's `notAfter`. Comparing them would
     * false-positive on every clean device.
     *
     * Forgers that mint their own leaves get caught by
     * [verifyChainSignatures] (their leaf won't verify against the
     * real intermediate's pubkey unless they've also forged the
     * intermediate, which then triggers this check on the
     * intermediate vs root edge).
     */
    fun validityPeriodsNested(chain: List<X509Certificate>): String? {
        // Compare only chain[1..n-1] pairs. With < 3 certs there's no
        // intermediate to compare, so defer.
        if (chain.size < 3) return null
        for (i in 1 until chain.size - 1) {
            val child = chain[i]
            val parent = chain[i + 1]
            if (child.notBefore.before(parent.notBefore)) {
                return "validity_child_predates_parent"
            }
            if (child.notAfter.after(parent.notAfter)) {
                return "validity_child_outlasts_parent"
            }
        }
        return null
    }

    // ---- freshness ---------------------------------------------------------

    /**
     * The TEE must echo our [nonce] in the attested
     * `attestationChallenge` field. If the parsed challenge differs,
     * the cert was minted for a different keygen request — i.e.
     * the chain is cached / forged and just papered over with our
     * pubkey.
     */
    fun challengeEchoes(parsed: ParsedKeyDescription?, nonce: ByteArray): String? {
        val attested = parsed?.attestationChallenge ?: return null
        if (!attested.contentEquals(nonce)) return "challenge_not_echoed"
        return null
    }

    /**
     * Compare two consecutive attestations [a] and [b] from the
     * same boot session, taken under different aliases + nonces.
     *
     * The TEE-meaningful per-keygen variables are the embedded
     * attestation challenge (we sent two different nonces) and the
     * leaf's SubjectPublicKey (we generated two distinct EC keys).
     * Both MUST differ across the two runs. If they don't, the
     * underlying attestation provider is replaying a cached chain
     * regardless of what we asked for.
     *
     * Notably, this does *not* compare `serialNumber` (hardcoded to 1
     * by AOSP KeyMint for every attestation cert) or the raw encoded
     * leaf bytes (would also flag any case where the challenge differs
     * but is the only meaningful difference — captured above with
     * better attribution).
     */
    fun freshnessAcrossAttestations(
        a: AttestationResult.Success,
        b: AttestationResult.Success,
    ): String? {
        val aLeaf = a.rawCerts.firstOrNull() ?: return null
        val bLeaf = b.rawCerts.firstOrNull() ?: return null

        // Pubkey-identical = the cached chain is being served
        // regardless of our keygen request (we asked for two distinct
        // keys; identical pubkeys means neither request was honoured).
        val aPub = runCatching { aLeaf.publicKey?.encoded }.getOrNull()
        val bPub = runCatching { bLeaf.publicKey?.encoded }.getOrNull()
        if (aPub != null && bPub != null && aPub.contentEquals(bPub)) {
            return "freshness_pubkey_identical"
        }
        // Challenge-identical = the cert wasn't minted for our request
        // (we sent two different nonces).
        val aCh = a.parsed?.attestationChallenge
        val bCh = b.parsed?.attestationChallenge
        if (aCh != null && bCh != null && aCh.contentEquals(bCh)) {
            return "freshness_challenge_identical"
        }
        return null
    }

    // ---- consistency -------------------------------------------------------

    /**
     * The leaf cert's SubjectPublicKey must match the public key
     * the AndroidKeyStore actually holds for our alias. If they
     * disagree, the chain we got was minted for some other key —
     * i.e. it's a replayed chain that just happens to be served
     * for our alias.
     */
    fun leafPubKeyMatchesKeystoreKey(
        leaf: X509Certificate,
        keystorePubKeyEncoded: ByteArray?,
    ): String? {
        if (keystorePubKeyEncoded == null) return null
        val leafPub = runCatching { leaf.publicKey?.encoded }.getOrNull()
            ?: return "leaf_pubkey_unreadable"
        if (!leafPub.contentEquals(keystorePubKeyEncoded)) {
            return "leaf_pubkey_mismatch"
        }
        return null
    }
}
