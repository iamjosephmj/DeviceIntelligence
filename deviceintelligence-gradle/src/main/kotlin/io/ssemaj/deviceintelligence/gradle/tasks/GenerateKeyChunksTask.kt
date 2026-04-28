package io.ssemaj.deviceintelligence.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.security.SecureRandom

/**
 * F7 (part 1) — generates the per-build XOR key and the Kotlin codegen that
 * makes it reachable from the runtime.
 *
 * Outputs:
 *   - `key.bin`  : raw 32-byte key consumed by [BakeFingerprintTask] at
 *                  encryption time. Build-private; never packaged into the APK.
 *   - 8 × `KeyChunkN.kt` : 4-byte slices of the key, each in a per-build
 *                  randomized sub-package of `io.ssemaj.deviceintelligence.gen.<random>`.
 *                  Static `grep KeyChunk` won't find them without first
 *                  finding the assembler.
 *   - `KeyAssembler.kt` : at the fixed FQN `io.ssemaj.deviceintelligence.gen.internal.KeyAssembler`,
 *                  imports each KeyChunkN from its random sub-package and
 *                  concatenates their bytes. The runtime decoder (F9) finds
 *                  this class via reflection.
 *
 * Why this is split from [BakeFingerprintTask]: the codegen output must be
 * compiled INTO `classes.dex` before [ComputeFingerprintTask] can hash the
 * final APK. If a single task did both codegen AND encryption, it would
 * need to run before kotlin-compile (for the codegen) AND after
 * package-and-sign (for hashing) — a fundamental cycle. Splitting breaks it:
 *
 *   generateKeyChunks  ─→  kotlin-compile  ─→  package  ─→  compute  ─→  bake
 *
 * Threat model framing: the XOR-with-codegen-chunks scheme is a *cost
 * amplifier*, not encryption. It defeats `unzip + grep` and naive blob
 * substitution. It does not defeat a determined reverse engineer with
 * IDA/Frida; runtime hooking detection is the job of the F16
 * `runtime_environment` detector.
 */
abstract class GenerateKeyChunksTask : DefaultTask() {

    @get:Input
    abstract val variantName: Property<String>

    /**
     * Raw 32-byte key. Build-private; consumed only by [BakeFingerprintTask].
     */
    @get:OutputFile
    abstract val keyFile: RegularFileProperty

    /**
     * Root of the generated Kotlin source tree (KeyChunk*.kt + KeyAssembler.kt).
     * Wired into the consumer's variant Kotlin source set by the plugin via
     * `variant.sources.kotlin.addGeneratedSourceDirectory(...)`.
     */
    @get:OutputDirectory
    abstract val generatedSrcDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val rng = SecureRandom()
        val key = ByteArray(KEY_SIZE).also { rng.nextBytes(it) }

        // -- write the raw key for the encryption task to consume
        val keyOut = keyFile.get().asFile.apply { parentFile.mkdirs() }
        keyOut.writeBytes(key)

        // -- generate per-chunk Kotlin sources in randomized sub-packages
        val srcRoot = generatedSrcDir.get().asFile.apply {
            // Wipe stale codegen so removed chunks never linger.
            if (exists()) deleteRecursively()
            mkdirs()
        }

        val subPkgs = (0 until CHUNKS).map { randomSubPackage(rng) }
        val chunkFqns = ArrayList<String>(CHUNKS)

        for (i in 0 until CHUNKS) {
            val pkg = "$GEN_PKG_PREFIX.${subPkgs[i]}"
            val cls = "KeyChunk$i"
            val pkgDir = File(srcRoot, pkg.replace('.', '/')).apply { mkdirs() }
            val from = i * CHUNK_SIZE
            val until = from + CHUNK_SIZE
            val chunk = key.sliceArray(from until until)
            File(pkgDir, "$cls.kt").writeText(renderChunkSource(pkg, cls, chunk))
            chunkFqns += "$pkg.$cls"
        }

        // -- generate the assembler at a FIXED FQN (runtime decoder finds it
        //    via Class.forName); imports the randomized chunk classes.
        val assemblerDir = File(srcRoot, ASSEMBLER_PKG.replace('.', '/')).apply { mkdirs() }
        File(assemblerDir, "${ASSEMBLER_CLASS}.kt").writeText(
            renderAssemblerSource(ASSEMBLER_PKG, ASSEMBLER_CLASS, chunkFqns)
        )

        logger.lifecycle(
            "io.ssemaj: generated $CHUNKS KeyChunk classes across ${subPkgs.distinct().size} unique sub-packages, plus $ASSEMBLER_PKG.$ASSEMBLER_CLASS (key=${KEY_SIZE}B)"
        )
    }

    private fun randomSubPackage(rng: SecureRandom): String {
        // 8 hex chars = 32 bits of entropy per sub-package. Prefixed with 'p'
        // so the Kotlin parser treats it as an identifier even if the random
        // hex starts with a digit.
        val bytes = ByteArray(4).also(rng::nextBytes)
        return "p" + bytes.joinToString("") { "%02x".format(it) }
    }

    private fun renderChunkSource(pkg: String, cls: String, chunk: ByteArray): String {
        val literal = chunk.joinToString(", ") { "0x%02X.toByte()".format(it) }
        return buildString {
            appendLine("// AUTO-GENERATED by io.ssemaj GenerateKeyChunksTask. DO NOT EDIT.")
            appendLine("// Build-time random; regenerated on every build.")
            appendLine("package $pkg")
            appendLine()
            appendLine("internal object $cls {")
            appendLine("    fun bytes(): ByteArray = byteArrayOf($literal)")
            appendLine("}")
        }
    }

    private fun renderAssemblerSource(pkg: String, cls: String, chunkFqns: List<String>): String {
        val imports = chunkFqns.joinToString("\n") { "import $it" }
        val concat = chunkFqns.indices.joinToString(",\n        ") { i ->
            val simple = chunkFqns[i].substringAfterLast('.')
            "*$simple.bytes()"
        }
        return buildString {
            appendLine("// AUTO-GENERATED by io.ssemaj GenerateKeyChunksTask. DO NOT EDIT.")
            appendLine("package $pkg")
            appendLine()
            appendLine(imports)
            appendLine()
            appendLine("/**")
            appendLine(" * Reassembles the per-build XOR key from KeyChunk0..${chunkFqns.size - 1}.")
            appendLine(" * Located at a fixed FQN so the runtime decoder can resolve it via")
            appendLine(" * Class.forName(\"$pkg.$cls\").")
            appendLine(" */")
            appendLine("internal object $cls {")
            appendLine("    fun assemble(): ByteArray = byteArrayOf(")
            appendLine("        $concat")
            appendLine("    )")
            appendLine("}")
        }
    }

    private companion object {
        const val KEY_SIZE: Int = 32
        const val CHUNKS: Int = 8
        const val CHUNK_SIZE: Int = KEY_SIZE / CHUNKS
        const val GEN_PKG_PREFIX: String = "io.ssemaj.deviceintelligence.gen"
        const val ASSEMBLER_PKG: String = "io.ssemaj.deviceintelligence.gen.internal"
        const val ASSEMBLER_CLASS: String = "KeyAssembler"
    }
}
