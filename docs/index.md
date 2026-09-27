---
template: home.html
social:
  cards_layout_options:
    title: Can this phone be trusted?
---

## Six languages. One verdict.

<div class="grid cards" markdown>

-   :material-language-kotlin:{ .lg .middle } __Kotlin — the reference__

    ---

    The original backend verifier, published on Maven Central as
    `tech.thessemaj:verifier-kotlin`. Scan + token flows, zero dependencies.

    [:arrow_forward: Quick start](backend.md)

-   :material-language-python:{ .lg .middle } __Python__

    ---

    Pip-installable port with the full token path and the scan-verification
    flow. Runs the same rooted-Pixel fixture, grades it the same.

    [:arrow_forward: Quick start](verifiers.md)

-   :material-language-typescript:{ .lg .middle } __TypeScript / Node__

    ---

    Feature-packaged npm module with a flat facade — token path complete,
    scan flow on the roadmap.

    [:arrow_forward: Quick start](verifiers.md)

-   :material-language-go:{ .lg .middle } __Go__

    ---

    Stdlib-only module: `crypto/ecdh` X25519, AES-GCM, `crypto/x509` chain
    verification, embedded registry and pinned roots.

    [:arrow_forward: Quick start](verifiers.md)

-   :material-language-php:{ .lg .middle } __PHP__

    ---

    PSR-4 package on ext-openssl + ext-sodium, self-contained test runner —
    no phpunit dependency.

    [:arrow_forward: Quick start](verifiers.md)

-   :material-language-ruby:{ .lg .middle } __Ruby__

    ---

    Gemspec-packaged port with a pure-Ruby RFC 7748 X25519 where the host
    OpenSSL binding falls short.

    [:arrow_forward: Quick start](verifiers.md)

</div>

## Three principles

<div class="grid cards" markdown>

-   :material-shield-search:{ .lg .middle } __Detection only__

    ---

    The device reports; the backend decides. Nothing is killed, blocked or
    degraded on-device — anything the app could enforce, a rooted attacker
    can remove.

-   :material-key-chain:{ .lg .middle } __Hardware-bound sessions__

    ---

    Hardware attestation runs once per session, keyed to the session id your
    backend issued. The attested key signs every later scan — a captured
    token is worthless anywhere else.

-   :material-eye-off:{ .lg .middle } __Opaque on the wire__

    ---

    Tokens carry `INTEL_XXXX` codes, not explanations. Detector names, probe
    mechanisms and evasion semantics never leave the device; your backend
    resolves them from the registry.

</div>

## Verify a token in 30 seconds

=== "Kotlin / JVM"

    ```kotlin
    val verifier = ScanVerifier()
    val result = verifier.verifyScan(token, sessionId, serverPrivateKey)
    when (result.decision) {
        Decision.TRUSTWORTHY -> allow()
        Decision.COMPROMISED -> stepUp(result.blockingSignals)
        Decision.REJECT      -> deny()
    }
    ```

=== "Python"

    ```python
    from deviceintelligence_verifier import TokenVerifier

    result = TokenVerifier().verify(token_hex, issued_nonce)
    if result.decision.value == "TRUSTWORTHY":
        allow()
    ```

=== "TypeScript / Node"

    ```ts
    import { TokenVerifier } from "./src/index.js";

    const result = new TokenVerifier().verify(tokenHex, issuedNonce);
    if (result.decision === "TRUSTWORTHY") allow();
    ```

=== "Go"

    ```go
    import verifier "github.com/iamjosephmj/DeviceIntelligence/verifier-go"

    res, _ := verifier.NewTokenVerifierBundled().Verify(tokenHex, issuedNonce)
    if res.Decision == verifier.DecisionTrustworthy {
        allow()
    }
    ```

=== "PHP"

    ```php
    use DeviceIntelligenceVerifier\TokenVerifier;

    $result = (new TokenVerifier())->verify($tokenHex, $issuedNonce);
    if ($result['decision'] === 'TRUSTWORTHY') allow();
    ```

=== "Ruby"

    ```ruby
    require "deviceintelligence_verifier"

    result = DeviceIntelligenceVerifier::TokenVerifier.new.verify(token_hex, issued_nonce)
    allow if result.decision == "TRUSTWORTHY"
    ```

## What the device checks

<div class="grid cards" markdown>

-   :material-cpu-64-bit:{ .lg .middle } __Hardware attestation__

    ---

    Keymaster KeyDescription chains verified against pinned Google roots,
    StrongBox vs TEE assurance, challenge-bound freshness.

-   :material-cellphone-lock:{ .lg .middle } __Verified boot__

    ---

    The TEE's own word on boot state and lock — a spoofer's self-report
    is cross-checked against hardware and flagged as INTEL_0055.

-   :material-hook:{ .lg .middle } __Hook frameworks__

    ---

    Inline prologues, GOT entries, JNIEnv tables, sealed memfds, linker<->maps
    divergence, behavioral syscall lies — mechanism-independent evidence.

-   :material-android:{ .lg .middle } __Root & clones__

    ---

    su binaries, Magisk artifacts, init mount namespaces, daemon sockets,
    test-keys builds, foreign APK mappings.

-   :material-monitor-shimmer:{ .lg .middle } __Emulators__

    ---

    Translated environments, CPU re-routing anomalies, hypervisor evidence,
    VM platform markers — probes that cannot fire on genuine silicon.

-   :material-package-variant-minus:{ .lg .middle } __Package tampering__

    ---

    Live APK vs build-time baseline: signature, entries, dex provenance,
    installer identity.

</div>

## Prove it

Every port runs the same rooted-Pixel capture (KernelSU + TrickyStore) and
grades it COMPROMISED, check-for-check. CI runs all six suites in parallel on
every push:

[:material-github: The suites](https://github.com/iamjosephmj/DeviceIntelligence/actions/workflows/unit-tests.yml)

Deep dive: the [verification specification](verification-spec.md), the
[signal catalogue](signal-catalogue.md), and the [verifier ports](verifiers.md)
page carry the full contract and per-language coverage.
