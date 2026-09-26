package tech.thessemaj.deviceintelligence.verifier

import java.io.File
import java.security.KeyFactory
import java.security.PrivateKey
import java.util.Base64

/**
 * Thin CLI wrapper so the library is runnable for parity checks / demos — the
 * Kotlin mirror of `python3 tools/server/verify_token.py`. The library itself
 * needs none of this; it's here only for convenience.
 *
 *   ./gradlew :verifier:run --args="scan <tokenHex|@file> <sessionId|@file> <serverPriv.pem> [session|@file]"
 *
 * `scan` is the current contract (schemaVersion 4). A BOOTSTRAP scan prints the
 * session facts it established; store them and pass them back as the 4th argument
 * on every later scan, exactly as a real backend would — the verifier keeps no
 * per-device state of its own. The document is the same one
 * `python3 tools/server/verify_token.py --scan` prints and reads.
 *
 * Retired paths, kept to replay historical captures:
 *
 *   ./gradlew :verifier:run --args="enroll <bundleHex|@file> <enrollChallenge|@file> [--expect-signer <sha256hex>]"
 *   ./gradlew :verifier:run --args="challenge <tokenHex|@file> <challenge|@file>"
 *
 * `enroll` accepts an optional `--expect-signer <sha256hex>` pin: enrollment hard-fails
 * when the attestation's TEE-computed app signer digest does not match it. Absent keeps
 * the unpinned dev behavior.
 */
fun main(args: Array<String>) {
    val signer = SessionSigner(LabKeys.SERVER_KEY)
    when (args.getOrNull(0)) {
        "scan" -> {
            if (args.size < 4) {
                System.err.println("usage: verifier scan <token|@file> <sessionId|@file> <serverPriv.pem> [session|@file]")
                kotlin.system.exitProcess(2)
            }
            val session = args.getOrNull(4)?.let { ScanSessionCodec.decode(readArg(it)) }
            val r = ScanVerifier().verifyScan(
                readArg(args[1]), readArg(args[2]), readServerPriv(args[3]), session)
            printScan(r)
            kotlin.system.exitProcess(
                if (!r.ok) 1 else if (!r.deviceIntegrityOk || r.signals.any { it.blocking }) 2 else 0)
        }
        "enroll" -> {
            val expectSigner = args.indexOf("--expect-signer").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
            val r = EnrollVerifier(signer, expectedSignerSha256 = expectSigner)
                .enroll(readArg(args[1]), readArg(args[2]))
            if (r.ok) {
                println(r.sessionId)
                kotlin.system.exitProcess(0)
            } else {
                System.err.println("ENROLL FAILED: ${r.reason}")
                r.checks.forEach { System.err.println("  [${if (it.ok) "PASS" else "FAIL"}] ${it.name}${if (it.detail.isNotEmpty()) "  (${it.detail})" else ""}") }
                kotlin.system.exitProcess(1)
            }
        }
        "challenge" -> {
            val r = TokenVerifier().verifyChallenge(readArg(args[1]), readArg(args[2]), signer)
            printResult(r)
            kotlin.system.exitProcess(if (r.decision == Decision.TRUSTWORTHY) 0 else if (r.decision == Decision.COMPROMISED) 2 else 1)
        }
        else -> {
            System.err.println(
                "usage: verifier scan <token|@file> <sessionId|@file> <serverPriv.pem> [session|@file]\n" +
                "       verifier enroll <bundle|@file> <enrollChallenge|@file> [--expect-signer <sha256hex>]   (retired)\n" +
                "       verifier challenge <token|@file> <challenge|@file>            (retired)")
            kotlin.system.exitProcess(2)
        }
    }
}

private fun printResult(r: VerificationResult) {
    println("=== authenticity (is the token genuine & fresh?) ===")
    r.checks.filter { it.kind == CheckKind.AUTH }.forEach { pr(it) }
    println("=== device integrity (what the TEE reports) ===")
    r.checks.filter { it.kind == CheckKind.INTEGRITY }.forEach { pr(it) }
    println("=== signals (device reports; policy decides) ===")
    r.device?.let { println("  device: ${it.model} / API ${it.api} / ${it.abi}") }
    if (r.signals.isEmpty()) println("  (none)")
    r.signals.forEach {
        val mark = if (it.blocking) "BLOCK" else "info "
        println("  [$mark] ${it.id} ${it.detector}/${it.kind} (${it.severity})")
        it.moduleId?.let { m -> println("          module:        $m") }
        it.path?.let { p -> println("          path:          $p") }
        if (it.linkedLibraries.isNotEmpty()) println("          links:         ${it.linkedLibraries.joinToString(", ")}")
        it.linksHookLib?.let { h -> println("          HOOKING LIB:   $h") }
        it.hookedSymbol?.let { sym -> println("          hooked symbol: $sym") }
        it.hookedBy?.let { by -> println("          hooked by:     $by") }
    }
    println()
    when (r.decision) {
        Decision.TRUSTWORTHY -> println("RESULT: ✅ TRUSTWORTHY")
        Decision.COMPROMISED -> println("RESULT: ⚠️  COMPROMISED — authentic token, but the device is compromised.")
        Decision.REJECT -> println("RESULT: ❌ REJECT — not a genuine/fresh binding; do not trust it.")
    }
}

private fun pr(c: Check) {
    val tag = if (c.ok) "PASS" else "FAIL"
    println("  [$tag] ${c.name}${if (c.detail.isNotEmpty()) "  (${c.detail})" else ""}")
}

/**
 * The backend X25519 private half (tools/keys/out/server-priv-<epoch>.pem). In
 * production this lives in an HSM/KMS; the file is the lab/dev loop.
 */
// Via ServerKey, not KeyFactory: this tool only ever runs on a desktop JVM where the
// XDH provider exists, but leaving the raw call here leaves the pattern to be copied
// into somewhere it does not — which is exactly how the Android 9 failure happened.
private fun readServerPriv(path: String): PrivateKey = ServerKey.from(File(path).inputStream())

private fun printScan(r: ScanResult) {
    println("=== authenticity (is the token genuine & fresh?) ===")
    r.checks.filter { it.kind == CheckKind.AUTH }.forEach { pr(it) }
    println("=== device integrity (what the TEE reports) ===")
    r.checks.filter { it.kind == CheckKind.INTEGRITY }.forEach { pr(it) }
    r.attestation?.let { a ->
        println("=== attestation (what the token says about its own binding) ===")
        println("  level=${a.level} signed=${a.signed} reason=${a.reason}" +
            (a.detail?.let { " detail=$it" } ?: "") +
            if (a.degraded) "   << DEGRADED — never evidence of a clean device" else "")
    }
    println("=== signals (device reports; policy decides) ===")
    if (r.signals.isEmpty()) println("  (none)")
    r.signals.forEach {
        println("  [${if (it.blocking) "BLOCK" else "info "}] ${it.id} ${it.detector}/${it.kind} (${it.severity})" +
            if (it.detail.isNullOrEmpty()) "" else "  ${it.detail}")
    }
    r.session?.let {
        println("=== session facts (store these; pass back as the 4th argument) ===")
        println("  " + ScanSessionCodec.encode(it))
    }
    println()
    when {
        !r.ok -> println("RESULT: ❌ REJECT — not a genuine/fresh binding" +
            (r.reason?.let { " ($it)" } ?: "") + "; do not trust it.")
        r.deviceIntegrityOk && r.signals.none { it.blocking } ->
            println("RESULT: ✅ TRUSTWORTHY — authentic token, TEE reports a clean device, no blocking signals.")
        else -> {
            val why = buildList {
                if (!r.deviceIntegrityOk) add("the TEE reports a compromised device (boot state / lock / security level)")
                val b = r.signals.filter { it.blocking }
                if (b.isNotEmpty()) add("${b.size} blocking signal(s): " + b.joinToString(", ") { "${it.id} (${it.detector}/${it.kind})" })
            }
            println("RESULT: ⚠️  COMPROMISED — authentic token, but " + why.joinToString(" and ") + ".")
        }
    }
}

private fun readArg(a: String): String =
    if (a.startsWith("@")) File(a.substring(1)).readText().trim() else a.trim()
