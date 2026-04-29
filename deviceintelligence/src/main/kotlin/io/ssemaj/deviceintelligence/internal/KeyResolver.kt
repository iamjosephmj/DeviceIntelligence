package io.ssemaj.deviceintelligence.internal

/**
 * Recovers the per-build XOR key used to encrypt the fingerprint blob.
 *
 * The key is split into N small chunks at build time (see
 * `io.ssemaj.deviceintelligence.gradle.tasks.GenerateKeyChunksTask`) which live in
 * randomly-named sub-packages, e.g.:
 *
 *   io.ssemaj.deviceintelligence.gen.p91a146bf.KeyChunk0
 *   io.ssemaj.deviceintelligence.gen.pc5e4b145.KeyChunk1
 *   ...
 *
 * A single fixed-FQN entry point — [ASSEMBLER_FQN] — knows how to
 * reassemble them into the full key byte array. We resolve it via
 * reflection so the runtime AAR has zero compile-time dependency on the
 * generated source set.
 *
 * R8/ProGuard rule:
 *   The consumer-rules.pro on this AAR keeps [ASSEMBLER_FQN] and its
 *   `assemble()` method intact even under aggressive minification. The
 *   generated chunk classes themselves can be (and are) freely renamed,
 *   because [ASSEMBLER_FQN]'s compiled bytecode references them
 *   directly and R8 rewrites those references atomically.
 *
 * Why reflection at all (vs. having the AAR define [ASSEMBLER_FQN])?
 *   [ASSEMBLER_FQN] is per-build; its body changes every build because
 *   the chunk sub-package names are random. The chunk source files only
 *   exist inside the consumer's `build/generated` tree, so the AAR can't
 *   compile-link against them.
 */
internal object KeyResolver {

    /**
     * Fixed FQN of the generated assembler. Must match
     * `GenerateKeyChunksTask.ASSEMBLER_PKG + "." + ASSEMBLER_CLASS`.
     */
    const val ASSEMBLER_FQN: String = "io.ssemaj.deviceintelligence.gen.internal.KeyAssembler"

    private const val ASSEMBLE_METHOD: String = "assemble"

    /**
     * Reflectively invokes `KeyAssembler.assemble()` and returns the raw
     * XOR key. Throws [KeyMissingException] on any failure — the asset
     * was injected by our plugin, so the assembler MUST be present; if
     * it's not, the APK has been re-bundled or had its codegen stripped.
     */
    fun assembleKey(): ByteArray {
        val cls = try {
            Class.forName(ASSEMBLER_FQN)
        } catch (cnfe: ClassNotFoundException) {
            throw KeyMissingException(
                "Could not resolve $ASSEMBLER_FQN; codegen was stripped or renamed",
                cnfe,
            )
        }

        val instance = try {
            cls.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
        } catch (t: Throwable) {
            throw KeyMissingException(
                "$ASSEMBLER_FQN is missing the Kotlin object INSTANCE field",
                t,
            )
        }

        val method = try {
            cls.getDeclaredMethod(ASSEMBLE_METHOD).apply { isAccessible = true }
        } catch (t: NoSuchMethodException) {
            throw KeyMissingException(
                "$ASSEMBLER_FQN.$ASSEMBLE_METHOD() not found (signature drift?)",
                t,
            )
        }

        val result = try {
            method.invoke(instance)
        } catch (t: Throwable) {
            throw KeyMissingException(
                "$ASSEMBLER_FQN.$ASSEMBLE_METHOD() threw at invocation",
                t,
            )
        }

        if (result !is ByteArray) {
            throw KeyMissingException(
                "$ASSEMBLER_FQN.$ASSEMBLE_METHOD() returned ${result?.javaClass?.name} (expected ByteArray)",
                cause = null,
            )
        }
        if (result.isEmpty()) {
            throw KeyMissingException(
                "$ASSEMBLER_FQN.$ASSEMBLE_METHOD() returned an empty key",
                cause = null,
            )
        }
        return result
    }

    /**
     * Couldn't recover the per-build key. Thrown for any failure mode
     * (missing class, missing method, wrong return type, runtime error).
     * Treated as a hard tampering signal by the integrity.apk detector.
     */
    class KeyMissingException(message: String, cause: Throwable?) : RuntimeException(message, cause)
}
