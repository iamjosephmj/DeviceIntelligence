// Convention-plugin build for the root project's modules (:deviceintelligence, 
// :samples:minimal, ). Included from the root settings.gradle.kts.
//
// The Gradle plugins for consumers (deviceintelligence-gradle) are separate
// composite builds and CANNOT use these conventions — each keeps its own
// minimal toolchain config.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
    // No explicit versionCatalogs here: the gradle/libs.versions.toml at this
    // build's root is imported implicitly as `libs` (see that file — the FULL
    // Gradle plugin artifacts live there, not in the consumer-facing root
    // catalog; keep versions in sync with the root catalog).
}

rootProject.name = "build-logic"
