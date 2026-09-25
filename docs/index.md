# DeviceIntelligence 🐍

DeviceIntelligence answers one question for your backend: **can this phone be trusted?**

A rooted, hooked or spoofed device lies to your app about everything — the files on disk, the values of its own properties, the provenance of the code running inside it. DeviceIntelligence sends a sensor into that minefield: on-device detectors probe hardware attestation, verified boot, hook frameworks, root, syscall filtering, package tampering and emulated environments, and report what they find as opaque `INTEL_XXXX` codes inside a signed, encrypted token.

Three principles shape everything:

- **Detection only.** The device reports; the backend decides. Nothing is killed, blocked, or degraded on-device — anything the app could enforce, a rooted attacker can remove. Enforcement lives where the attacker isn't.
- **Hardware-bound sessions.** Hardware attestation runs once per session, keyed to the session id *your* backend issued at login. The attested key signs every later scan, so a captured token is worthless anywhere else — and every token names the user it belongs to.
- **Opaque on the wire.** The token carries codes, not explanations. Detector names, probe mechanisms and evasion semantics never leave the device; your backend resolves them from the registry and grades what it sees.

## Quick start

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
- [Keys & licences](keys.md) — the two files, rotation, dev vs release.
- [Signal catalogue](signal-catalogue.md) — every `INTEL_XXXX` code, decoded.
