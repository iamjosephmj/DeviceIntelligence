# DeviceIntelligence token-verification specification

The canonical contract every backend verifier port implements. The reference
implementation is `verifier-kotlin/src/main/kotlin/` (Kotlin/JVM); the ports are
`verifiers/python`, `verifiers/node`, `verifiers/go`, `verifiers/rust`. A port
that grades a token differently from the reference is wrong — the fixtures in
`verifiers/fixtures/` and the golden vectors in `verifiers/tests/golden.json`
pin the parity.

All key material is per-deployment: the device holds only the X25519 **public**
half (`server.key`), the backend holds the **private** half.

---

## 1. Token envelope

Two generations exist on the wire; the leading bytes discriminate.

### v1 (legacy, decode-only — the scan path rejects it)

- Lowercase hex, no prefix. Plaintext recovery:

  ```
  key = SHA256("intel-verdict-token-key-v1")            // ASCII, no NUL
  keystream_block(b) = SHA256(key || u32le(b))           // b = 0,1,2,...
  plain[i] = cipher[i] XOR keystream_block(i / 32)[i % 32]
  ```

### v2 (current)

- `"2:"` + lowercase hex of: `version(1) || epoch(1) || eph_pub(32) || nonce(12) || ct || tag(16)`
- `shared = X25519(server_priv_scalar, eph_pub)` — eph_pub is little-endian;
  clear the high bit of its last byte before use (RFC 7748)
- `key = HKDF-SHA256(ikm=shared, salt=nonce, info="intel-token-v2" || epoch, len=32)`
- `plain = AES-256-GCM-open(key, iv=nonce, ct||tag, aad=version||epoch||eph_pub)` — the AAD
  is exactly the 34-byte prefix of the payload

## 2. Plaintext layout

```
<signed_content JSON>"\n--BINDING\n"["SIG\x1F<hex>"\n]["CERT\x1F<hex>"\n]...
                         ["XLEVEL_SB\x1F<hex>"\n]["XLEVEL_TEE\x1F<hex>"\n]
```

- The SIG line carries the ECDSA P-256 signature (DER, hex) over the exact
  `signed_content` bytes (UTF-8).
- CERT lines are the attestation chain, leaf first.
- XLEVEL_SB / XLEVEL_TEE carry the cross-level chains used by the keybox-reuse
  forensics. An empty SIG with a `--BINDING` present marks a DEGRADED token.

## 3. signed_content JSON

| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | int | 3 (enroll/challenge era), 4 (scan era) |
| `bootstrap` | bool | scan path: true = first cold-start scan (carries the chain) |
| `sessionId` | string | must equal the id the backend issued |
| `attestedKey` | hex string | SPKI of the key the bootstrap attested |
| `app` | {`package`, `signer`} | self-reported; cross-checked against the attested identity |
| `device` | {`api`, `abi`, `model`, `vbs`, `blocked`, `vbmeta`, `sbFeature`} | self-report |
| `signals` | [{`id`, `severity`, `detail`}] | opaque codes + enrichment tokens |
| `attestation` | {`level`, `signed`, `reason`, `detail`} | the device's own binding report |
| `fp` | {`id`,`aid`,`lvl`,`build`,`kernel`,`patch`,`installer`} | device fingerprint |

## 4. Signal resolution

- Look each `signals[].id` up in the registry (`signals-registry.json`).
- Unknown codes keep their id with `detector = kind = "?"` and empty title.
- Legacy `SIG_`-prefixed ids normalize to `INTEL_` + suffix before lookup.
- `severity` comes from the signal itself when present; the registry value is
  the fallback.
- `detail` enrichment tokens parse into attributes for the keys:
  `path, module_id, needed, links_hook_lib, hooked_symbol, hooked_by, target,
  ondisk_confirmed, on_disk_prologue, trampoline_class, object, base, seals,
  key, get, area, hook_stub_regions, region_count`.

## 5. Policy

```
isBlocking(id, severity, kind, hookStubRegions):
  1. id in allow                      -> false
  2. id in block                      -> true
  3. kind == rwx_memory_mapping:
       hookStubRegions > 0            -> true      (confirmed hook pool)
       observeUnconfirmedRwx && 0     -> false     (opt-in downgrade)
  4. severity.upper() in {CRITICAL}   -> true
  5. else                             -> false
```

Defaults: `allow = {}`, `block = {}`, `blockSeverities = {CRITICAL}`,
`observeUnconfirmedRwx = false`, `requireStrongBox = false`,
`maxPatchAgeDays = 365`.

## 6. Scan verification flow (schemaVersion 4)

Order is normative — checks run in this order and short-circuit:

1. `v2 envelope` — the token starts with `"2:"`; else fail `"not a v2 token"`.
2. `envelope opens` — the v2 open succeeds; else `"envelope did not open"`.
3. `binding present` — a `--BINDING` separator exists; else `"unbound"`.
4. `signed content is JSON` — parses to a non-empty object.
5. Signals resolve (always reported, even past failures).
6. `session id matches issued` — recorded; a mismatch fails AFTER the degraded
   gate, so degraded evidence still ships.
7. **Degraded gate** — `attestation.signed != "ATTESTED"` or the SIG line is
   empty: the token is unauthenticated by construction. It fails (`ok=false`),
   carries its evidence, and never touches session facts.
8. **Bootstrap** (`bootstrap=true`):
   - CERT lines parse to a chain.
   - Each cert signed by the next; the top either matches a pinned Google root
     (SHA-256 of DER) or verifies by its key. Fail = `"chain does not reach a
     pinned Google root"`.
   - The KeyDescription attestationChallenge equals the issued session-id bytes.
   - `attestedKey` present and hex.
   - Facts are COMPUTED and CARRIED: assurance (2=StrongBox, 1=TEE, else
     SOFTWARE), boot state, lock, cross-level reuse, CRL revocation, property
     mismatch, boot-state spoofer, StrongBox-chain-missing, software-attested,
     patch levels, fingerprint.
   - Adjudication (below) runs on the carried facts.
9. **Steady-state** (`bootstrap=false`):
   - A carried session MUST exist (`"no bound key for session"`).
   - A SIG line MUST be present (`"no signature"`).
   - ECDSA P-256 over `signed_content` MUST verify against the session's
     attested key.
   - Adjudication runs on the carried facts.
10. **Adjudication** — see §7.

## 7. Adjudication

- **AUTH failures → REJECT**: chain not trusted, revoked keybox, cross-level
  keybox reuse, device-property mismatch, boot-state spoofer.
- **INTEGRITY failures → COMPROMISED**: assurance SOFTWARE (or explicit
  software attestation → INTEL_0056), boot state not Verified, device unlocked.
- The returned `ScanResult`: `ok`, `deviceIntegrityOk`, `decision`,
  `session` (bootstrap only), `checks`, `signals` (device + app-identity +
  carried + patch staleness), `reason`, `fingerprint`, `attestation`.

## 8. Attestation extension parsing

OID `1.3.6.1.4.1.11129.2.1.17`; `getExtensionValue` returns the KeyDescription
DER wrapped in one OCTET STRING. KeyDescription element indexes:

- [1] securityLevel (ENUM)
- [4] attestationChallenge (OCTET STRING)
- [6] softwareEnforced AuthorizationList
- [7] teeEnforced AuthorizationList — preferred over [6] everywhere

AuthorizationList tags (EXPLICIT, high-tag-number `BF 85 NN`):
RootOfTrust `[704]` (inner SEQUENCE: verifiedBootKey, deviceLocked BOOL,
verifiedBootState ENUM, ...), attestationApplicationId `[709]`, osVersion
`[705]`, osPatchLevel `[706]`, vendorPatchLevel `[718]`, bootPatchLevel
`[719]`, attestationId brand/device/product/manufacturer/model
`[710..712,716,717]`.

Chain rule: pairwise signature verification leaf→…→top, then the top either
matches a pinned Google root by SHA-256(DER) or verifies by its key.

## 9. Patch signals

- INTEL_0050: the OLDEST attested patch level (os YYYYMM, vendor/boot YYYYMMDD)
  older than `maxPatchAgeDays`.
- INTEL_0019: the self-reported `patch` month (YYYY-MM) contradicts the attested
  osPatchLevel month. Absence fails open.

## 10. App-identity cross-check

- Attested identity (tag 709) vs the self-reported `app` block:
  package must be in the attested list AND one attested digest must equal the
  self-reported signer (case-insensitive). Disagreement → INTEL_0046 (CRITICAL).
- Identity agreeing but not licensed → INTEL_0037 (HIGH), never 0046.
- Absence on either side fails open (no signal).

## 11. Carried-fact signals

- bootStateSpoofer → INTEL_0055 (CRITICAL)
- crossLevelReuse → INTEL_0016 (CRITICAL)
- strongboxChainMissing → INTEL_0045 (VERY_LOW)
- softwareAttested → INTEL_0056 (CRITICAL)

## 12. Session facts for later scans

The bootstrap returns the `ScanSession` facts the caller stores and passes back:
`attestedKey, attestedApp, assurance, bootState, deviceLocked, chainTrusted,
keyboxRevoked, crossLevelReuse, devicePropMismatch, bootStateSpoofer,
strongboxChainMissing, softwareAttested, osPatchLevel, vendorPatchLevel,
bootPatchLevel, fingerprint`.
