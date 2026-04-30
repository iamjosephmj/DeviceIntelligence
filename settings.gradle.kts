pluginManagement {
    // includeBuild is load-bearing here: the JitPack publish job runs
    // `./gradlew :deviceintelligence:publishToMavenLocal -x test`, which
    // evaluates this settings file and then `:samples:minimal/build.gradle.kts`,
    // which applies `id("io.ssemaj.deviceintelligence") version "<VERSION_NAME>"`.
    // In that worker the matching plugin is NOT yet on JitPack (we are trying
    // to publish it in the same job), so without composite-build substitution
    // the entire root build aborts and the runtime AAR never gets published.
    // The composite-build path also gives in-tree devs an iterate-on-plugin
    // loop without local mavenLocal publishes.
    includeBuild("deviceintelligence-gradle")
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
}

rootProject.name = "DeviceIntelligence"

// In-tree library module. The Gradle plugin auto-detects this via
// `rootProject.findProject(":deviceintelligence")` and substitutes
// `project(":deviceintelligence")` for the otherwise-fetched JitPack AAR
// (see DeviceIntelligencePlugin.addRuntimeDep). External consumers without
// this module get the published AAR instead — same one-line consumer DSL.
include(":deviceintelligence")
include(":samples:minimal")
// Test-only artefacts used to verify the G5/G6 anti-hooking
// detectors. These are NOT shipped to consumers — they live
// alongside the sample app purely for in-tree CTF verification.
include(":samples:xposed-api-stubs")
include(":samples:lsposed-tester")
