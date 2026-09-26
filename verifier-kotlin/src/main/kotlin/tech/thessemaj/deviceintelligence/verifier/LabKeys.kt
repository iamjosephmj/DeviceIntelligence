package tech.thessemaj.deviceintelligence.verifier

/** Fixed lab HMAC key for stateless session tokens — shared by the CLI, the fixture
 *  tests, and the Python reference verifier so sessions issued by one open in another.
 *  Lab/dev only; a real backend uses a secret, rotated key. */
object LabKeys {
    val SERVER_KEY: ByteArray = "intel-lab-session-key-v1".toByteArray(Charsets.UTF_8)
}
