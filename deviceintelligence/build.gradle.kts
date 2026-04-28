plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

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
}

dependencies {
    testImplementation(libs.junit)
}
