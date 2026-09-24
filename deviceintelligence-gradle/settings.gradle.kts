dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

rootProject.name = "deviceintelligence-gradle"

// Spec 08 carve: the closed, secret-bearing key derivation lives in a separate
// JAR (`:baker`) the (open-source) plugin depends on, so the env-KEK phrases
// never ship in the published plugin source.
include(":baker")
