plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// Read coordinates from gradle.properties so JitPack (which sets
// VERSION_NAME from the git tag) and `publishToMavenLocal` (used
// for smoke-testing) share the same source of truth.
val publishGroup: String = providers.gradleProperty("GROUP_ID").get()
val publishVersion: String = providers.gradleProperty("VERSION_NAME").get()
val libraryArtifactId: String = providers.gradleProperty("LIBRARY_ARTIFACT_ID").get()

group = publishGroup
version = publishVersion

android {
    namespace = "io.ssemaj.deviceintelligence"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    defaultConfig {
        // Android 9 is the floor: the F14 hardware key-attestation
        // surface and several PackageManager APIs we rely on
        // (GET_SIGNING_CERTIFICATES, signingInfo) all landed in API
        // 28. Below that, large chunks of the library degraded to
        // null / inconclusive without giving the consumer real value.
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17", "-fno-exceptions", "-fno-rtti")
                arguments(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_PLATFORM=android-28",
                )
            }
        }

        // Wire VERSION_NAME from gradle.properties through BuildConfig so
        // the runtime can report the exact published coordinate it was
        // built under. TelemetryReport.libraryVersion reads this; the
        // value lines up with the JitPack tag + Maven coordinate, which
        // means a backend correlating reports has a single version
        // identifier across plugin, library, and report payload.
        buildConfigField("String", "LIBRARY_VERSION", "\"$publishVersion\"")
    }

    buildFeatures {
        // We only emit one BuildConfig field (LIBRARY_VERSION). Enabling
        // buildConfig is the cheapest way to get a const into the runtime
        // — far simpler than a generated Kotlin source task for one value.
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            consumerProguardFiles("consumer-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    // First-class AGP publishing hook (8.0+). Tells AGP which variant
    // becomes the published `release` artifact, and asks it to also
    // produce the sources + javadoc jars expected by Maven Central
    // / Sonatype tooling. JitPack doesn't strictly require these but
    // shipping them makes IDE source-attachment work for consumers
    // (and costs nothing).
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

dependencies {
    // Coroutines is the lone runtime dep. Exposed as `api` because
    // the public surface (`suspend collect()`, `Flow<TelemetryReport>
    // observe()`) returns coroutines types — consumers that touch
    // them need the symbols on their compile classpath without
    // having to repeat the dependency themselves. Adds ~80 KB to a
    // consumer APK; if the consumer already depends on coroutines
    // (95%+ of modern Android apps), Gradle dedupes.
    api(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

// AGP creates the `release` software component lazily during evaluation
// of the android {} block, so the publishing block has to run after the
// android {} block has materialised it.
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = publishGroup
                artifactId = libraryArtifactId
                version = publishVersion

                pom {
                    name.set("DeviceIntelligence")
                    description.set(
                        "Android device-intelligence telemetry SDK: hardware-backed " +
                            "key attestation, bootloader integrity, root indicators, " +
                            "in-process tampering, emulator probe, app-cloner signals " +
                            "— emitted as a single deterministic JSON report."
                    )
                    url.set("https://github.com/iamjosephmj/DeviceIntelligence")
                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
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
        }
        // GitHub Actions only (GITHUB_REPOSITORY + GITHUB_TOKEN set by the runner).
        repositories {
            System.getenv("GITHUB_REPOSITORY")?.let { gpr ->
                maven {
                    name = "GitHubPackages"
                    url = uri("https://maven.pkg.github.com/$gpr")
                    credentials {
                        username = System.getenv("GITHUB_ACTOR").orEmpty()
                        password = System.getenv("GITHUB_TOKEN").orEmpty()
                    }
                }
            }
        }
    }
}
