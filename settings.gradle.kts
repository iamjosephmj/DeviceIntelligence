pluginManagement {
    // includeBuild is load-bearing here: the JitPack publish job runs
    // `./gradlew :deviceintelligence:publishToMavenLocal -x test`, which
    // evaluates this settings file and then `:samples:minimal/build.gradle.kts`,
    // which applies `id("tech.thessemaj.deviceintelligence") version "<VERSION_NAME>"`.
    // In that worker the matching plugin is NOT yet on JitPack (we are trying
    // to publish it in the same job), so without composite-build substitution
    // the entire root build aborts and the runtime AAR never gets published.
    // The composite-build path also gives in-tree devs an iterate-on-plugin
    // loop without local mavenLocal publishes.
    //
    // build-logic is the convention-plugin build for THIS build's modules
    // (:deviceintelligence, :samples:minimal) — shared JVM/Android config.
    // The consumer-facing plugin below is a separate composite build and
    // intentionally does not use it.
    includeBuild("build-logic")
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

// JitPack runs an init script that resolves every configuration (listDeps). Parallel
// project execution plus AGP/Kotlin can trigger ConcurrentModificationException while
// iterating configurations (common with Gradle 8.13 + composite builds).
if (!System.getenv("JITPACK").isNullOrEmpty()) {
    gradle.startParameter.isParallelProjectExecutionEnabled = false
}

// In-tree library module. The Gradle plugin auto-detects this via
// `rootProject.findProject(":deviceintelligence")` and substitutes
// `project(":deviceintelligence")` for the otherwise-fetched published AAR
// (see DeviceIntelligencePlugin.addRuntimeDep). External consumers without
// this module get the published AAR instead — same one-line consumer DSL.
include(":deviceintelligence")
// Backend verifier — pure Kotlin/JVM library. The sample app bundles it for the
// on-device demo loop and the SDK androidTests decode tokens with it.
include(":verifier")
include(":samples:minimal")
