pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven(url = uri("https://jitpack.io"))
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "io.ssemaj.deviceintelligence") {
                useModule(
                    "com.github.iamjosephmj.DeviceIntelligence:" +
                        "deviceintelligence-gradle:${requested.version}",
                )
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven(url = uri("https://jitpack.io"))
    }
}

rootProject.name = "DeviceIntelligence"

// In-tree library module (tests, local AAR). The sample app consumes the
// published runtime from JitPack instead — see samples/minimal/build.gradle.kts
// (`disableAutoRuntimeDependency` + explicit implementation) so it matches
// external consumers. To hack on the Gradle plugin from this repo, temporarily
// add `includeBuild("deviceintelligence-gradle")` above and remove the
// resolutionStrategy / JitPack plugin resolution for that session.
include(":deviceintelligence")
include(":samples:minimal")
