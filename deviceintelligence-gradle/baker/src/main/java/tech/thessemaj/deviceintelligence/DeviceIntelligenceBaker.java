package tech.thessemaj.deviceintelligence.baker;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The build-time secret holder for the deviceintelligence env-KEK key derivation
 * (spec 08 carve). This is the ONE piece that must NOT live in the open-source
 * plugin: it embeds the env-KEK phrases, which are also baked (OLLVM-encrypted)
 * into {@code libdicore.so}. Shipping them in the public plugin source would let
 * anyone derive the fingerprint / dex-string keys from the per-build seed,
 * collapsing the scheme. Keeping them in this separate (closed) JAR keeps them out
 * of the published plugin source — "delay, not deny" (the JAR is still
 * JVM-decompilable, the same posture as the {@code .so} copy).
 *
 * <p>The open-source plugin depends on this JAR and calls {@link #fpKey}; it does
 * the (non-secret) framing/XOR with the returned key.
 */
public final class DeviceIntelligenceBaker {

    private DeviceIntelligenceBaker() {}

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * env-KEK derivation: {@code K = SHA256(seed XOR SHA256(phrase))}. MUST stay
     * byte-identical to the native side ({@code apk_integrity_jni.cpp::fp_derive_key}
     * and {@code binding.cpp::derive_dex_key_gated}), or the device can't decrypt what
     * the build encrypts. {@code seed} is the per-build 32-byte random prepended to
     * the shipped blob.
     */
    private static byte[] derive(byte[] seed, String phrase) {
        if (seed.length < 32) {
            throw new IllegalArgumentException("env-KEK seed must be >= 32 bytes");
        }
        byte[] mix = sha256(phrase.getBytes(StandardCharsets.US_ASCII));
        byte[] eff = new byte[32];
        for (int i = 0; i < 32; i++) {
            eff[i] = (byte) (seed[i] ^ mix[i]);
        }
        return sha256(eff);
    }

    /**
     * Fingerprint-blob key (matches {@code fp_derive_key}, phrase
     * {@code dicore-fpkey-mix-v1}). The plugin XOR-encrypts {@code fingerprint.bin}
     * with this.
     */
    public static byte[] fpKey(byte[] seed) {
        return derive(seed, "dicore-fpkey-mix-v1");
    }

}
