plugins {
    `java-library`
}

// Compile-only stubs of the Xposed module API
// (`de.robv.android.xposed.*`). Consumed by `:samples:lsposed-tester`
// as a `compileOnly` dependency so the stubs never end up in the
// dex — at runtime, the LSPosed framework injects the real
// implementation classes into the host process under the same
// fully-qualified names.
//
// Existence of this sub-module (rather than putting the stubs
// inline in the LSPosed module) is what guarantees that the
// stubs don't shadow the framework's classes once the module is
// loaded.

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
