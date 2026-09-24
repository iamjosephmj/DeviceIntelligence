package tech.thessemaj.deviceintelligence.buildtools

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Spec 04 — env-derived-KEK protection of the signer baseline.
 *
 * No stored key: ship only { per-build random seed, ciphertext }.
 * `KEK = SHA256( seed XOR SHA256("dicore-kek-mix-v1") )`; the key is
 * re-derived at runtime inside the OLLVM-obfuscated native code
 * (apk_self_check.cpp::expected_signer). SHA-256 = system BoringSSL native ==
 * Java MessageDigest here, so the two halves round-trip exactly (a mismatch
 * would crash genuine builds, so it's correctness-gated by the on-device
 * genuine-survives test).
 *
 * Input: `-Pdeviceintelligence.expectedSigner=<hex>`; with no property set the generated
 * header disables the baseline check entirely (plain dev builds).
 *
 * Lives in build-logic so deviceintelligence/build.gradle.kts declares WHAT the build
 * produces without embedding crypto in a build script. Call it at
 * configuration time (as before): CMake reads the include dir from cppFlags.
 */
object BaselineBlob {

    /**
     * Writes `baseline_blob.h` into [genDir]: a disabled stub when
     * [expectedSigner] is null, otherwise the seed-XOR-mix/keystream envelope
     * of the expected signer. Returns the generated header file.
     */
    fun writeHeader(genDir: File, expectedSigner: String?): File {
        genDir.mkdirs()
        val header = genDir.resolve("baseline_blob.h")
        if (expectedSigner == null) {
            header.writeText("#pragma once\n#define DICORE_BASELINE_ENABLED 0\n")
            return header
        }

        fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        val plain = expectedSigner.toByteArray(Charsets.US_ASCII)
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val mix = sha256("dicore-kek-mix-v1".toByteArray(Charsets.US_ASCII))
        val eff = ByteArray(32) { (seed[it].toInt() xor mix[it].toInt()).toByte() }
        val kek = sha256(eff)
        val cipher = ByteArray(plain.size)
        var off = 0; var c = 0
        while (off < plain.size) {
            val ks = sha256(kek + byteArrayOf(c.toByte()))
            var j = 0
            while (j < 32 && off + j < plain.size) {
                cipher[off + j] = (plain[off + j].toInt() xor ks[j].toInt()).toByte(); j++
            }
            off += 32; c++
        }
        fun bytes(b: ByteArray) = b.joinToString(",") { (it.toInt() and 0xff).toString() }
        header.writeText(
            "#pragma once\n#define DICORE_BASELINE_ENABLED 1\n" +
                "static const int kBaselineLen=${plain.size};\n" +
                "static const unsigned char kBaselineSeed[]={${bytes(seed)}};\n" +
                "static const unsigned char kBaselineCipher[]={${bytes(cipher)}};\n",
        )
        return header
    }
}
