/**
 * Pure JVM module convention (:verifier, and any future plain-Kotlin module):
 * Kotlin/JVM, source + bytecode pinned to 17, toolchain 17.
 */
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}
