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

// ---- Maven Central publication (same pipeline as the AAR + plugin) --------
// Coordinates from the root gradle.properties: tech.thessemaj:verifier-kotlin:<VERSION_NAME>.
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.JavadocJar

group = providers.gradleProperty("GROUP_ID").get()
version = providers.gradleProperty("VERSION_NAME").get()

mavenPublishing {
    configure(KotlinJvm(javadocJar = JavadocJar.Javadoc(), sourcesJar = true))
    publishToMavenCentral(automaticRelease = true)
    // Sign only when a key is supplied. Keyless publishToMavenLocal keeps working.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }
    coordinates(providers.gradleProperty("GROUP_ID").get(), "verifier-kotlin", providers.gradleProperty("VERSION_NAME").get())
    pom {
        name.set("DeviceIntelligence Verifier (Kotlin/JVM)")
        description.set(
            "Zero-dependency Kotlin/JVM backend half of DeviceIntelligence: opens the " +
                "signed, encrypted scan tokens, resolves the opaque INTEL_XXXX codes " +
                "against the signal registry, and grades the verdict."
        )
        url.set("https://github.com/iamjosephmj/DeviceIntelligence")
        licenses {
            license {
                name.set("Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)")
                url.set("https://creativecommons.org/licenses/by-nd/4.0/legalcode")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("iamjosephmj")
                name.set("Joseph James")
                url.set("https://github.com/iamjosephmj")
            }
        }
        scm {
            url.set("https://github.com/iamjosephmj/DeviceIntelligence")
            connection.set("scm:git:git://github.com/iamjosephmj/DeviceIntelligence.git")
            developerConnection.set("scm:git:ssh://git@github.com/iamjosephmj/DeviceIntelligence.git")
        }
    }
}
