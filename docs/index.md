# DeviceIntelligence 🐍

Device-integrity detection for Android. On-device detectors grade the environment — hardware attestation, verified boot, hook frameworks, root, emulators, APK tampering — and report what they find as opaque `INTEL_XXXX` codes inside a signed, encrypted token. Your backend opens it and decides.

## Install

Apply the Gradle plugin; it adds the runtime AAR, hashes your APK at build time, and re-signs:

```kotlin
plugins {
    id("tech.thessemaj.deviceintelligence") version "3.0.0"
}
```

Provision one X25519 keypair on your machine — never in a build, never on a device:

```sh
python3 tools/keys/gen-dev-licence.py <applicationId> <out-dir>
```

Ship `server.key` as an app asset at `assets/tech.thessemaj.deviceintelligence/server.key`; the private half belongs to your backend. Then three calls:

```kotlin
DeviceIntelligence.initialize(application)      // once, local, ~3 ms
DeviceIntelligence.setSession(sessionId)        // once per session, ~175 ms, off the UI thread
val token = DeviceIntelligence.scan("checkout") // per request, ~150 ms
myBackend.submit(token)
```

All three are suspend functions. Send the token even when the first two return false — a degraded token names the failure, and your backend grades it.

## Verdicts

- **TRUSTWORTHY** — authentic and clean.
- **COMPROMISED** — authentic, but the device reports an untrustworthy state.
- **REJECT** — forged, replayed, or re-signed.

## Where next

- [Android integration](android.md) — repositories, plugin styles, per-call contracts.
- [Backend verification](backend.md) — the `verifier` module and the decision flow.
- [Keys & licences](keys.md) — what the two files are, rotation, dev vs release.
- [Signal catalogue](signal-catalogue.md) — every `INTEL_XXXX` code, decoded.
