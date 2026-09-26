package tech.thessemaj.deviceintelligence.verifier

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

/**
 * Stateless session tokens (spec §6.2/§7). A sessionId is
 *   base64url(payloadJson) "." base64url(HMAC-SHA256(serverKey, payloadJson))
 * so any backend holding serverKey can verify it with no per-session state.
 *
 * A session also EXPIRES: [open] rejects a token older than [maxAgeSeconds] (by its
 * HMAC-protected `issuedAt`, epoch seconds), so `verifyChallenge` REJECTs it exactly
 * as it does a forged one — matching the spec's "forged/expired -> REJECT". Statelessness
 * means we can't revoke a single session, so a bounded lifetime is the only thing that
 * caps how long a captured/relayed sessionId stays usable. [now] is injectable for tests.
 */
class SessionSigner(
    serverKey: ByteArray,
    private val maxAgeSeconds: Long = DEFAULT_MAX_AGE_SECONDS,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val key = SecretKeySpec(serverKey, "HmacSHA256")
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val b64d = Base64.getUrlDecoder()

    fun issue(s: Session): String {
        val payload = """{"pinnedKey":"${s.pinnedKeySpkiHex}","assurance":"${s.assurance}",""" +
            """"boot":"${s.bootState}","locked":${s.deviceLocked},"issuedAt":${s.issuedAt},""" +
            """"chainTrusted":${s.chainTrusted},""" +
            """"kbRevoked":${s.keyboxRevoked},"xlReuse":${s.crossLevelReuse},"sbMissing":${s.strongboxChainMissing},""" +
            """"propMismatch":${s.devicePropMismatch},"bootSpoofer":${s.bootStateSpoofer},"swAttest":${s.softwareAttested}}"""
        val bytes = payload.toByteArray(Charsets.UTF_8)
        return b64.encodeToString(bytes) + "." + b64.encodeToString(mac(bytes))
    }

    fun open(sessionId: String): Session? = runCatching {
        val dot = sessionId.indexOf('.')
        if (dot < 0) return null
        val bytes = b64d.decode(sessionId.substring(0, dot))
        val gotMac = b64d.decode(sessionId.substring(dot + 1))
        if (!MessageDigest.isEqual(mac(bytes), gotMac)) return null   // constant-time
        val o = Json.parseObject(String(bytes, Charsets.UTF_8))
        val issuedAt = o["issuedAt"] as Long
        // Expiry: the HMAC guarantees `issuedAt` is server-set (a client can't backdate
        // it), so this only bounds replay of a genuine session. A missing/non-positive
        // stamp is treated as invalid. A future `issuedAt` (minor clock skew) stays valid.
        if (issuedAt <= 0L || now() - issuedAt > maxAgeSeconds) return null
        Session(
            pinnedKeySpkiHex = o["pinnedKey"] as String,
            assurance = Assurance.valueOf(o["assurance"] as String),
            bootState = o["boot"] as String,
            deviceLocked = o["locked"] as Boolean,
            issuedAt = issuedAt,
            chainTrusted = o["chainTrusted"] as? Boolean ?: true,
            keyboxRevoked = o["kbRevoked"] as? Boolean ?: false,
            crossLevelReuse = o["xlReuse"] as? Boolean ?: false,
            strongboxChainMissing = o["sbMissing"] as? Boolean ?: false,
            devicePropMismatch = o["propMismatch"] as? Boolean ?: false,
            bootStateSpoofer = o["bootSpoofer"] as? Boolean ?: false,
            // `sbDowngrade` (INTEL_0039) is retired. Sessions issued before that still
            // carry the field; it is simply not read — the HMAC covers the stored bytes,
            // so those sessions keep verifying.
            softwareAttested = o["swAttest"] as? Boolean ?: false,
        )
    }.getOrNull()

    private fun mac(bytes: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(key) }.doFinal(bytes)

    companion object {
        /** Default session lifetime: 24h. Integrators tune this to their replay-risk budget. */
        const val DEFAULT_MAX_AGE_SECONDS: Long = 24L * 60 * 60
    }
}
