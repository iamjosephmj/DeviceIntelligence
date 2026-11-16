/**
 * Pure Java module convention (:corpus:red-team:xposed-api-stubs): source +
 * bytecode pinned to 17. No Kotlin plugin — the stubs are .java by design.
 */
plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
