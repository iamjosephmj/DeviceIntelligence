# DeviceIntelligence

Device-integrity detection for Android. On-device detectors grade the environment — hardware attestation, verified boot, hook frameworks, root, emulators, APK tampering — and report findings as opaque `INTEL_XXXX` codes inside a signed, encrypted token. Your backend opens it and decides.

<p align="left">
  <a href="https://github.com/iamjosephmj/DeviceIntelligence/actions/workflows/unit-tests.yml"><img alt="CI" src="https://github.com/iamjosephmj/DeviceIntelligence/actions/workflows/unit-tests.yml/badge.svg?branch=main"></a>
  <img alt="Min SDK" src="https://img.shields.io/badge/minSdk-28-green.svg?style=flat">
  <img alt="Kotlin" src="https://img.shields.io/badge/Kotlin-2.2-7F52FF.svg?style=flat&logo=kotlin&logoColor=white">
  <img alt="Maven Central" src="https://img.shields.io/maven-central/v/tech.thessemaj/deviceintelligence?style=flat">
  <a href="https://github.com/sponsors/iamjosephmj"><img alt="GitHub Sponsors" src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-DB61A2.svg?style=flat&logo=githubsponsors"></a>
</p>

<p align="left">
  <a href="verifier-kotlin/"><img alt="Kotlin verifier" src="https://img.shields.io/badge/Kotlin-2.2-7F52FF.svg?style=flat&logo=kotlin&logoColor=white"></a>
  <a href="verifier-python/"><img alt="Python verifier" src="https://img.shields.io/badge/Python-3.12-3776AB.svg?style=flat&logo=python&logoColor=white"></a>
  <a href="verifier-node/"><img alt="Node verifier" src="https://img.shields.io/badge/Node-20-339933.svg?style=flat&logo=nodedotjs&logoColor=white"></a>
  <a href="verifier-go/"><img alt="Go verifier" src="https://img.shields.io/badge/Go-1.22-00ADD8.svg?style=flat&logo=go&logoColor=white"></a>
  <a href="verifier-php/"><img alt="PHP verifier" src="https://img.shields.io/badge/PHP-8.3-777BB4.svg?style=flat&logo=php&logoColor=white"></a>
  <a href="verifier-ruby/"><img alt="Ruby verifier" src="https://img.shields.io/badge/Ruby-3.2-CC342D.svg?style=flat&logo=ruby&logoColor=white"></a>
  <a href="verifier-rust/"><img alt="Rust verifier" src="https://img.shields.io/badge/Rust-1.75-DEA584.svg?style=flat&logo=rust&logoColor=white"></a>
</p>

📚 **[Full documentation](https://iamjosephmj.github.io/DeviceIntelligence/)** — Android integration, backend verification, keys & licences, the decoded signal catalogue, and the verification spec.

## The device reports. Your backend decides.

Three principles, no exceptions:

1. **Detection only** — nothing is killed or blocked on-device; enforcement lives where the attacker isn't.
2. **Hardware-bound sessions** — attestation runs once per login, keyed to *your* session id; the attested key signs every later scan.
3. **Opaque on the wire** — tokens carry codes, not explanations. Probe mechanisms never leave the device.

## Backend verifiers — seven languages, one verdict

Every port grades the same rooted-device capture identically. CI runs all seven suites in parallel on every push.

| Language | Path | Install | Test |
|---|---|---|---|
| Kotlin *(reference)* | [`verifier-kotlin/`](verifier-kotlin/) | Maven Central: `tech.thessemaj:verifier-kotlin:3.0.0` | `./gradlew :verifier-kotlin:test` |
| Python | [`verifier-python/`](verifier-python/) | `pip install -e verifier-python` | `pytest verifier-python/tests` |
| TypeScript | [`verifier-node/`](verifier-node/) | `npm install ./verifier-node` | `npm test` |
| Go | [`verifier-go/`](verifier-go/) | vendored module | `go test ./...` |
| PHP | [`verifier-php/`](verifier-php/) | Composer path repo | `php tests/run_tests.php` |
| Ruby | [`verifier-ruby/`](verifier-ruby/) | gemspec | minitest suite |
| Rust | [`verifier-rust/`](verifier-rust/) | vendored crate | `cargo test` |

## Quick start

Android (the Gradle plugin adds the runtime AAR, hashes your APK, re-signs):

```kotlin
plugins { id("tech.thessemaj.deviceintelligence") version "3.0.0" }
```

Backend (any language — this is the whole integration):

```kotlin
val result = ScanVerifier().verifyScan(token, sessionId, serverPrivateKey)
when (result.decision) {
    Decision.TRUSTWORTHY -> allow()
    Decision.COMPROMISED -> stepUp(result.blockingSignals)
    Decision.REJECT      -> deny()
}
```

Keys, provisioning and the full flow: [the docs](https://iamjosephmj.github.io/DeviceIntelligence/).

## License

    DeviceIntelligence — Copyright (c) 2026 Joseph James (github.com/iamjosephmj)

Licensed under [CC BY-ND 4.0](LICENSE).
