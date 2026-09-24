// Top-level build file. Plugins are declared here as `apply false` and applied
// in the relevant subprojects.

buildscript {
    // The Hilt Gradle plugin's AggregateDepsTask calls JavaPoet API that only exists
    // from 1.13. Something older on the plugin classpath (AGP's own transitive
    // JavaPoet) otherwise wins conflict resolution and the task dies with
    // `NoSuchMethodError: com.squareup.javapoet.ClassName.canonicalName()`.
    // Forcing it here is the documented workaround; drop it once AGP ships 1.13+.
    dependencies {
        classpath("com.squareup:javapoet:1.13.0")
    }
    repositories {
        google()
        mavenCentral()
    }
}
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    // Pure-JVM Kotlin for the :verifier backend library (shares the Kotlin version
    // with kotlin-android; declared here so the module can apply it without a version).
    alias(libs.plugins.kotlin.jvm) apply false

    // NOTE: the old licence-keygen composite build was NOT carried
    // over in the rebrand. Licence provisioning now lives in tools/keys/
    // (gen-dev-licence.py + gen-licence-key.sh); install the resulting
    // server.key at samples/minimal/src/main/assets/tech.thessemaj.deviceintelligence/.
}
