# Backend verification

The [`verifier`](https://github.com/iamjosephmj/DeviceIntelligence/tree/main/verifier) module is plain Kotlin/JVM with zero external dependencies. Add it to your backend project:

```sh
cp -r DeviceIntelligence/verifier <your-backend>/verifier
```

```kotlin
// settings.gradle.kts
include(":verifier")
```

```kotlin
// build.gradle.kts
dependencies { implementation(project(":verifier")) }
```

## Verify a scan

```kotlin
val verifier = ScanVerifier()
val result = verifier.verifyScan(
    token,                                  // the token string from the device
    sessionId,                              // the session id you issued
    serverPrivateKeyStream,                 // server-priv-<epoch>.pem — PEM or raw DER PKCS#8
    storedSession,                          // the ScanSession you stored, null on first contact
)
```

The private key is parsed once and cached, so per-request verification does not re-parse. There is also an overload taking a `java.security.PrivateKey` for keys from an HSM or platform keystore.

## Bootstrap vs steady-state

Every scan is one of two shapes, handled by the same call:

- **Bootstrap** — the first scan of a cold start. Carries the full hardware attestation chain bound to your session id. On success, `result.session` is non-null: store that `ScanSession` on your session record. It holds the attested key (hex SPKI), the attested app identity, the assurance level (StrongBox / TEE / software), boot state and lock state.
- **Steady-state** — every later scan. Signed by the key the bootstrap attested; pass the stored `ScanSession` back in and the verifier checks the signature against it. Stateless by construction: nothing per-device is kept in the verifier itself.

## What you get back

A `ScanResult`:

- `ok` — every authenticity check passed. `false` means REJECT: forged, replayed, or re-signed. Do not trust the contents.
- `deviceIntegrityOk` — every integrity check passed: the device is honestly reporting *and* is in a trustworthy state. A token can be perfectly authentic while this is false — a COMPROMISED device, not a forged token.
- `decision` — **TRUSTWORTHY** (`ok && deviceIntegrityOk`), **COMPROMISED** (authentic but untrustworthy state), or **REJECT** (not authentic).
- `signals` — the resolved `INTEL_XXXX` findings, each with its detector family, severity and blocking flag.
- `checks` — every auth and integrity check that ran, in order: the audit trail for the decision.
- `fingerprint` — the device fingerprint the token carried, when present.

## Verdicts

- **TRUSTWORTHY** — authentic and clean.
- **COMPROMISED** — authentic, but the device reports an untrustworthy state.
- **REJECT** — forged, replayed, or re-signed.
