// Closed "baker" — the build-time secret-bearing piece of the DeviceIntelligence
// pipeline (spec 08). Holds the env-KEK phrases + key derivation that MUST match
// the .so; shipped as a separate JAR the (open-source) plugin depends on, so the
// phrases never live in the published plugin source. Plain `java-library` (the
// derivation is trivial JDK crypto) — avoids the Kotlin-plugin-version conflict
// with the parent kotlin-dsl build, and has zero dependencies.
plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
