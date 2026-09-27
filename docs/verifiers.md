# Backend verifiers in seven languages

Every backend port implements the same contract and grades the same fixtures
identically: the rooted-Pixel capture must come back COMPROMISED on all seven,
check-for-check. A port that disagrees with the Kotlin reference is wrong —
the shared fixtures in [`verifiers/fixtures/`](https://github.com/iamjosephmj/DeviceIntelligence/tree/main/verifiers/fixtures)
pin the parity, and each port's CI job runs its suite on every push.

| Language | Location | Install | Test command | Coverage |
|---|---|---|---|---|
| Kotlin (reference) | `verifier-kotlin/` | Maven Central: `tech.thessemaj:verifier-kotlin` | `./gradlew :verifier-kotlin:test` | token + scan flows |
| Python | `verifier-python/` | `pip install -e verifier-python` | `pytest verifier-python/tests` | token flow |
| TypeScript / Node | `verifier-node/` | `npm install verifier-node` (not yet on npm) | `npm test` in `verifier-node` | token flow |
| Go | `verifier-go/` | vendored module `verifier-go/` | `go test ./...` | token flow |
| PHP | `verifier-php/` | Composer path repo `verifier-php/` | `php tests/run_tests.php` | token flow |
| Ruby | `verifier-ruby/` | gemspec `verifier-ruby/` | `ruby -Ilib -Itest` suite | token flow |
| Rust | `verifier-rust/` | vendored crate `verifier-rust/` | `cargo test` | token flow |

All seven expose the same three-layer verdict — **REJECT** unless the token is
authentic, **COMPROMISED** when the TEE (or a blocking signal) reports a
compromised device, **TRUSTWORTHY** only when everything clears.

## Quick starts

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
    import { TokenVerifier } from "deviceintelligence-verifier";

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

=== "Rust"

    ```rust
    use deviceintelligence_verifier::{decision, TokenVerifier};

    let result = TokenVerifier::bundled()?.verify(&token_hex, &issued_nonce);
    if result.decision == decision::TRUSTWORTHY {
        allow();
    }
    ```

## What the ports cover today

The token path is complete everywhere: envelope decoding (v1 keystream +
v2 ECIES), binding parsing, the attestation-extension walk, chain-to-pinned-
root verification, signal resolution against the registry, policy grading,
codec round-trips and the session-signing contract.

The scan-verification flow (bootstrap/steady-state adjudication, CRL
revocation, cross-level keybox forensics, patch staleness) is ported in
Kotlin, Python, Node and Go; PHP, Ruby and Rust currently ship the token
path and gain the scan flow as their next milestone.

## Adding a new port

1. Mirror the feature layout (`tokens/`, `attestation/`, `policy/`, `model/`).
2. Port the tests from `verifier-python/tests/` — same vectors, same fixtures.
3. The rooted-Pixel capture must grade COMPROMISED, identically. A port that
   disagrees with the reference is wrong, whatever its own tests say.
