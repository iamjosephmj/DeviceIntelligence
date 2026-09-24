plugins {
    id("deviceintelligence.jvm")   // convention: Kotlin/JVM, Java 17, toolchain 17
    application       // core Gradle plugin — for the optional CLI (`:verifier:run`)
}

application {
    mainClass.set("tech.thessemaj.deviceintelligence.verifier.CliKt")
}

// Pure Kotlin/JVM backend library: decrypt + verify + interpret a verdict token
// server-side. ZERO runtime dependencies (JDK crypto + a tiny hand-rolled JSON/DER
// reader), so a backend can drop the jar in with no transitive-dependency risk.
// Not an Android module and never shipped to the app consumer.

dependencies {
    testImplementation(libs.junit)
}

// Single source of truth: copy the signal registry from tools/ into the library's
// resources at build time, so the Kotlin verifier and the on-device emitter stay
// in lock-step (no second copy to drift).
val registrySrc = rootProject.file("tools/registry/signals-registry.json")
val crlSrc = rootProject.file("tools/crl/attestation-crl.txt")
tasks.named<ProcessResources>("processResources") {
    from(registrySrc) { into(".") }
    from(crlSrc) { into(".") }
    inputs.file(registrySrc)
    inputs.file(crlSrc)
}

tasks.test {
    useJUnit()
    testLogging { events("passed", "failed", "skipped") }
}
