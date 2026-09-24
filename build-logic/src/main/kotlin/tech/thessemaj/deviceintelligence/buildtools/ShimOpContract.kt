package tech.thessemaj.deviceintelligence.buildtools

import java.io.File

/**
 * The FrameworkShim op-code contract check (the JNI twin of the signal-registry
 * freshness guard).
 *
 * `FrameworkShim.q(op, arg)` (Kotlin) and `fw_q`/`jvm_asset` (framework_shim.cpp)
 * share a fixed integer op-code table. It is a two-sided contract with NO single
 * source of truth: native passes literals, Kotlin dispatches on literals. The
 * failure mode when they drift is nasty — native calls an op the `when` no longer
 * handles, gets `null` back, and every up-call DEGRADES FAIL-OPEN: detectors run
 * blind with zero errors anywhere.
 *
 * This scanner extracts the literal op sets from both sides and fails when the
 * native side calls an op Kotlin does not handle. It is a static heuristic:
 * ops passed through a variable on the native side are invisible to it (the
 * current code always passes literals), and Kotlin arms with no native caller
 * are reported, not failed (an arm can be deliberately retained, like `NativeBridge.g`).
 */
object ShimOpContract {

    data class Report(
        val kotlinOps: Set<Int>,
        val nativeOps: Set<Int>,
    ) {
        val nativeCallsUnhandled: Set<Int> get() = nativeOps - kotlinOps
        val kotlinHandlesUncalled: Set<Int> get() = kotlinOps - nativeOps
    }

    /**
     * Ops dispatched in `FrameworkShim.q`'s `when`. The scan is deliberately
     * restricted to the body of `q` — the rest of the file has unrelated
     * int-`when`s (keygen levels, base encodings) that would pollute the set.
     */
    fun kotlinOps(shimKt: File): Set<Int> {
        val text = shimKt.readText()
        val start = text.indexOf("fun q(op: Int")
        require(start >= 0) { "${shimKt.path}: FrameworkShim.q not found — the up-call entry point was renamed or moved" }
        val endMarker = "}.getOrNull()"
        val end = text.indexOf(endMarker, start)
        require(end > start) { "${shimKt.path}: could not find the end of q() (`.getOrNull()`); adjust the scanner" }
        val body = text.substring(start, end + endMarker.length)
        return Regex("""(?m)^\s+(\d+)\s*->""")
            .findAll(body)
            .map { it.groupValues[1].toInt() }
            .toSet()
    }

    /**
     * Ops the native side passes as literals to the up-call helpers:
     * `fw_q(e, N, ...)`, the `fw_q_*` wrapper family, and `jvm_asset(N)`.
     */
    fun nativeOps(cppRoot: File): Set<Int> {
        // Matches fw_q(...), fw_q_string(3), fw_session_...(e, 14, ...) style
        // helper calls whose FIRST-or-second argument is a literal int, plus
        // jvm_asset(6). Variable-passed ops are invisible by design (documented).
        val call = Regex("""\b(?:fw_q\w*|jvm_asset)\s*\(\s*(?:\w+\s*,\s*)?(\d+)\s*[,)]""")
        val out = sortedSetOf<Int>()
        cppRoot.walkTopDown()
            .filter { it.isFile && it.extension in listOf("cpp", "cc", "h", "hpp") }
            .forEach { f ->
                call.findAll(f.readText()).forEach { out += it.groupValues[1].toInt() }
            }
        return out
    }

    fun scan(shimKt: File, cppRoot: File): Report =
        Report(kotlinOps(shimKt), nativeOps(cppRoot))

    /**
     * @throws IllegalStateException when the native side calls a shim op the
     * Kotlin `when` does not handle (silent fail-open null on device).
     */
    fun check(shimKt: File, cppRoot: File) {
        val r = scan(shimKt, cppRoot)
        if (r.nativeCallsUnhandled.isNotEmpty()) {
            throw IllegalStateException(
                "FrameworkShim op-code contract violated.\n" +
                    "  native calls ops ${r.nativeCallsUnhandled.sorted()} that " +
                    "FrameworkShim.q does not handle — every such up-call returns null and " +
                    "degrades fail-open with no error.\n" +
                    "  kotlin handles : ${r.kotlinOps.sorted()}\n" +
                    "  native calls   : ${r.nativeOps.sorted()}\n" +
                    "Add the missing arm(s) in deviceintelligence/src/main/kotlin/tech/thessemaj/deviceintelligence/internal/FrameworkShim.kt " +
                    "(or drop the native call site)."
            )
        }
        if (r.kotlinHandlesUncalled.isNotEmpty()) {
            // Report-only: an arm may be retained deliberately (e.g. `NativeBridge.g`'s
            // prologue-verify anchor), and the native scan cannot see
            // variable-passed ops. The point is a loud note, not a gate.
            println(
                "deviceintelligence: shim ops handled but not seen in native sources " +
                    "(informational): ${r.kotlinHandlesUncalled.sorted()}"
            )
        }
    }
}
