package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

class SessionSignerTest {
    private val issuedAt = 1787220000L
    // Fixed clock 100s after issuance so round-trip/tamper tests are deterministic.
    private val signer = SessionSigner("test-server-key".toByteArray(), now = { issuedAt + 100 })
    private val session = Session("30591301deadbeef", Assurance.STRONGBOX, "Verified", true, issuedAt)

    @Test fun round_trips() {
        val id = signer.issue(session)
        assertEquals(session, signer.open(id))
    }

    @Test fun rejects_expired() {
        val id = signer.issue(session)
        // A verifier whose clock is one second past the max age rejects the same token.
        val late = SessionSigner("test-server-key".toByteArray(),
            now = { issuedAt + SessionSigner.DEFAULT_MAX_AGE_SECONDS + 1 })
        assertNull(late.open(id))
    }

    @Test fun rejects_zero_timestamp() {
        val stampless = Session("30591301deadbeef", Assurance.STRONGBOX, "Verified", true, 0L)
        assertNull(signer.open(signer.issue(stampless)))
    }

    @Test fun rejects_tampered_payload() {
        val id = signer.issue(session)
        val (p, mac) = id.split(".", limit = 2).let { it[0] to it[1] }
        // flip a char in the payload, keep the old MAC
        val forged = p.dropLast(1) + (if (p.last() == 'A') 'B' else 'A') + "." + mac
        assertNull(signer.open(forged))
    }

    @Test fun rejects_wrong_key() {
        val id = signer.issue(session)
        assertNull(SessionSigner("different-key".toByteArray()).open(id))
    }

    @Test fun rejects_malformed() {
        assertNull(signer.open("not-a-session"))
        assertNull(signer.open("only-one-part."))
    }
}
