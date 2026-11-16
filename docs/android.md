# Android integration

Make sure Maven Central is resolvable:

```kotlin
// settings.gradle.kts
pluginManagement { repositories { mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { mavenCentral() } }
```

Apply the plugin; it adds the runtime AAR, hashes your APK at build time, and re-signs:

```kotlin
plugins {
    id("tech.thessemaj.deviceintelligence") version "3.0.0"
}
```

Builds using the legacy `buildscript` style instead take the plugin as an explicit classpath dependency:

```kotlin
// root build.gradle.kts
buildscript {
    repositories { mavenCentral() }
    dependencies { classpath("tech.thessemaj:deviceintelligence-gradle:3.0.0") }
}
// and in the app module:
apply(plugin = "tech.thessemaj.deviceintelligence")
```

No plugin? Add the AAR directly and handle the fingerprint baking yourself:

```kotlin
dependencies {
    implementation("tech.thessemaj:deviceintelligence:3.0.0")
}
```

## The three calls

Drop `server.key` into `app/src/main/assets/tech.thessemaj.deviceintelligence/` (see [Keys & licences](keys.md)). Then:

```kotlin
DeviceIntelligence.initialize(application)      // once, local, ~3 ms
DeviceIntelligence.setSession(sessionId)        // once per session, ~175 ms, off the UI thread
val token = DeviceIntelligence.scan("checkout") // per request, ~150 ms
myBackend.submit(token)
```

All three are suspend functions. What each one returns and what it means:

- **`initialize(application): Boolean`** — loads the native core and validates the licence. `false` is not a stop signal: if the blob parsed but was rejected (expired, wrong package), the key inside it is still usable and `scan()` emits a degraded token that names the rejection (`INTEL_0038`). Send it — at the backend, no token is indistinguishable from a network error, and silence helps nobody but the attacker. The one hard case: the asset missing or unparseable — then there is nothing to encrypt to and `scan()` returns `""`.
- **`setSession(sessionId): Boolean`** — the id must come from your backend and be opaque, unpredictable and per-session: it is the challenge the hardware attestation binds to, so a guessable or reused value quietly removes replay protection. This call performs the one TEE/StrongBox keygen (why it is slow and off the UI thread). `false` still leaves `scan()` usable — it emits a degraded token naming the missing binding.
- **`scan(scenarioName, nonce = ""): String`** — the first scan after `setSession` carries the full attestation certificate chain; every later scan signs with the attested key and is cheap. Pass a fresh server `nonce` per request if your session ids cannot be made unpredictable. Returns `""` only in the one case above.

Not on coroutines: `tech.thessemaj.deviceintelligence.dx.NativeBridge` is the blocking core underneath — same three calls, and `NativeBridge.s(FrameworkShim::class.java)` must run once before anything else.

## Where the sample fits

[`samples/minimal`](https://github.com/iamjosephmj/DeviceIntelligence/tree/main/samples/minimal) is a working end-to-end integration — device and backend in one process.
