# App Bundle (AAB) bundle-mode integrity — design

Status: approved design (v1). Date: 2026-06-29.
Port of the bundle-mode integrity feature from DeviceIntelligenceRASP (shipped there in 4.0.0)
into the original DeviceIntelligence library, adapted to this repo's layout.

## Summary

DeviceIntelligence's build-baked APK-integrity layer (the `fingerprint.bin`: signer-cert
pin + ZIP-entry hashes) is **APK-only**. When an app ships as an **Android App Bundle
(`.aab`)** through Google Play, Play re-splits, **re-encodes**, and **re-signs** the
delivered APKs — which breaks the integrity layer three ways. This feature adds a parallel
**bundle mode** that produces integrity coverage which survives Play's pipeline, with no
false positives, while leaving the existing APK path unchanged.

The runtime cloner detector (`runtime.cloner`, `/proc`-based) is already AAB-agnostic and
is untouched. This feature concerns the **build-baked integrity / repackage defense** only.

## Motivation — the three APK-only failure modes (current code)

1. **Transform never runs for AAB.** The fingerprint transform is wired only to
   `SingleArtifact.APK` (`deviceintelligence-gradle/.../DeviceIntelligencePlugin.kt:308`,
   `toTransformMany(SingleArtifact.APK)`). `bundleRelease` never injects `fingerprint.bin`
   → runtime `fingerprint_asset_missing` CRITICAL (`.../internal/ApkIntegrityDetector.kt:221-232`).
2. **Signer pin is the upload key.** The baseline pins the developer's upload-key cert
   (`InstrumentApkTask.kt:437-488` → `signerCertSha256`). Play re-signs splits with the
   **app-signing key**, so the runtime signer check fails → `apk_signer_mismatch` on every
   Play install.
3. **Entry hashes are compressed bytes.** Both `ApkHasher.kt:59-66` and native
   `zip_parser.cpp hash_all_entries` (lines 83-173) hash the **compressed** on-disk body of
   each ZIP entry. Play re-deflates split APKs, so the compressed bytes differ → mass
   `apk_entry_modified` CRITICAL.

## Design (v1) — bundle mode, native decompressed hashing (Option A)

A separate **bundle-mode** path, mutually exclusive with APK mode per variant, enabled by
the developer. It pins what is **stable across Play's pipeline**:

### Signal 1 — signer membership (anti repackage/resign)
Bake an **allow-set** of signer certs = the upload-keystore cert ∪ the developer-supplied
Play **app-signing** cert SHA-256(s). At runtime every cert observed in the installed
`base.apk` signing block must be a **member** of the allow-set (membership, not the
APK-mode equality). A repackager who resigns under their own key is not in the set →
`apk_signer_mismatch` CRITICAL. (If the allow-set is empty, the signer check is skipped —
documented fail-open; dex/.so hashing is then the sole anchor.)

### Signal 2 — decompressed code-entry integrity across splits (anti code-patch)
Bake the **decompressed** SHA-256 of every code-bearing entry — `classes*.dex` and
`lib/<abi>/*.so` — from the bundle's base module. At runtime, for each baked entry, locate
it across `base.apk` **+ all `splitSourceDirs`** and compare its **decompressed** SHA-256.
Mismatch → `apk_entry_modified` CRITICAL; absent everywhere → `apk_entry_removed` HIGH. No
`apk_entry_added` check (splits legitimately carry many non-baked entries). Resources /
manifest are not byte-pinned in bundle mode (Play re-encodes them) — they are covered
transitively by the signer pin (editing them requires re-signing).

**Why decompressed:** Play re-deflates entries, so only the **inflated payload** is stable
between build time and the installed device. DI currently hashes compressed bytes and has
**no inflater in native** — so a native inflate path is net-new (Option A, chosen for parity
with DI's existing native APK-mode hashing and its tamper-resistance posture).

### Entry-name normalization (build vs runtime keys)
The bundle's base module stores code at `base/dex/classes*.dex` and `base/lib/<abi>/*.so`.
The **installed** base/split APKs expose those same files as `classes*.dex` and
`lib/<abi>/*.so`. `AabHasher` therefore keys `bundleEntryHashes` by the **installed-APK
entry name**: `base/dex/<f>` → `<f>`, `base/lib/<abi>/<f>` → `lib/<abi>/<f>`. (Mirror the
RASP `AabHasher.kt` mapping.)

## Components / files

### Plugin (`deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/`)
- **Create** `internal/AppBundleOptions.kt` — `@Nested` DSL: `enabled: Property<Boolean>`
  (default false) + `playSigningCertSha256: SetProperty<String>` with a
  `fun playSigningCertSha256(vararg hex: String)` that normalizes (strip `:`, lowercase).
- **Modify** `DeviceIntelligenceExtension.kt` (currently lines 11-84) — add a `@Nested`
  `appBundle: AppBundleOptions` + `fun appBundle(action: Action<AppBundleOptions>)`.
- **Modify** `internal/Fingerprint.kt` — add v3 fields `bundleMode: Boolean = false`,
  `bundleEntryHashes: Map<String,String> = emptyMap()`; bump `SCHEMA_VERSION` 2 → 3 (line 63).
- **Modify** `internal/FingerprintCodec.kt` — bump `FORMAT_VERSION` 2 → 3 (line 66); append a
  v3 tail in `encode()` (after the v2 tail, ~line 133): `writeBoolean(bundleMode)` then sorted
  `bundleEntryHashes`; in `decode()` add `if (formatVersion >= 3) { ... }` (after ~line 228).
  `MIN_SUPPORTED_FORMAT_VERSION` stays 1 (v1/v2 blobs decode, fields default).
- **Create** `internal/AabHasher.kt` — read the `.aab` zip; for `base/dex/classes*.dex` and
  `base/lib/<abi>/*.so`, compute **decompressed** SHA-256 (`ZipFile.getInputStream` inflates),
  keyed by normalized installed-entry name (above). (Mirror RASP `AabHasher.kt`.)
- **Create** `internal/AabSigner.kt` — re-sign the modified `.aab` with JDK
  `jdk.security.jarsigner.JarSigner` (SHA-256), reusing the existing `PrivateKey` +
  `List<X509Certificate>` from `InstrumentApkTask.loadSigningMaterial()` (lines 437-488).
  apksig cannot sign `.aab`; no bundletool dependency is added. (Mirror RASP `AabSigner.kt`.)
- **Create** `internal/BundleFingerprintBuilder.kt` — assemble the v3 `Fingerprint`:
  `bundleMode=true`, `entries=emptyMap()`, `bundleEntryHashes` from `AabHasher`,
  `signerCertSha256 = (uploadCertHashes + playPins).distinct()`, and the existing
  `nativeLibInventoryByAbi` / `dicoreTextSha256ByAbi` (read from the bundle's `base/lib/`).
  Encrypt with the **same** `seed ‖ XOR(encode(fp), key(seed))` envelope and per-build key
  chunks as APK mode. (Mirror RASP `BundleFingerprintBuilder.kt`.)
- **Create** `tasks/BundleIntegrityTask.kt` — `DefaultTask` wired to `SingleArtifact.BUNDLE`
  (single-file `.use(task).wiredWith(inputFile,outputFile).toTransform(SingleArtifact.BUNDLE)`):
  (1) `BundleFingerprintBuilder.build`, (2) inject `base/assets/io.ssemaj.deviceintelligence/fingerprint.bin`
  (STORED) into the `.aab` — full repack, drop `META-INF/` + any old fingerprint, **no
  directory entries** (bundletool rejects them), (3) `AabSigner.sign`. (Mirror RASP
  `BundleIntegrityTask.kt`.)
- **Modify** `DeviceIntelligencePlugin.kt` — at variant time read `ext.appBundle.enabled`. If
  true: register `BundleIntegrityTask` on `SingleArtifact.BUNDLE` and **skip** the APK
  `InstrumentApkTask` transform (lines 303-311) for that variant; reuse the same key-chunk
  generation + signing-material resolution (lines 159-180). If false: unchanged.

### Native (`deviceintelligence/src/main/cpp/dicore/`)
- **Modify** `CMakeLists.txt` — add `find_library(z-lib z)` and link it (next to log/android/dl,
  ~lines 64-71). NDK ships zlib.
- **Modify** `zip_parser.{h,cpp}` — add `hash_entry_decompressed(map, count, entryName, out32)`:
  locate the entry via the central directory; if STORED, SHA-256 the raw body; if DEFLATED,
  `inflate` (raw-deflate, `inflateInit2(-MAX_WBITS)`) into a bounded streaming buffer and
  SHA-256 the inflated bytes. Bounds-checked against the mapped file size; fail-closed to
  "not found"/empty on any zlib error (caller treats as not-found → fail-open).
- **Modify** `jni_bridge.cpp` + `NativeBridge.kt` — add
  `external fun apkEntryDecompressedHash(path: String, entryName: String): String?`
  (mmap the apk, call `hash_entry_decompressed`, return hex or null). Looped per entry in
  Kotlin; no multi-path JNI needed.

### Runtime (`deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/`)
- **Modify** `ApkIntegrityDetector.kt` — after decoding the fingerprint, if `fp.bundleMode`
  take a **bundle branch instead of** the APK-mode entry diff:
  - **Signer membership:** observed certs (`NativeBridge.apkSignerCertHashes(base)`) each must
    be in `fp.signerCertSha256` (skip if the baked set is empty) → else `apk_signer_mismatch`
    CRITICAL.
  - **Entry integrity:** `paths = [applicationInfo.sourceDir] + (applicationInfo.splitSourceDirs ?: [])`;
    for each `(name -> hash)` in `fp.bundleEntryHashes`, find the first `path` where
    `NativeBridge.apkEntryDecompressedHash(path, name)` is non-null; compare → `apk_entry_modified`
    CRITICAL on mismatch, `apk_entry_removed` HIGH if found in none.
  - Keep the `expectedSourceDirPrefix` (`/data/app/`) check. Keep pushing
    `dicoreTextSha256ByAbi` / `nativeLibInventoryByAbi` to native (unchanged).
- **Modify** runtime `internal/Fingerprint.kt` + `internal/FingerprintCodec.kt` — mirror the
  plugin v3 fields + decoder guard (decode-only side).

## Data flow

```
BUILD (bundle mode):
  bundleRelease -> SingleArtifact.BUNDLE (.aab)
    BundleIntegrityTask:
      AabHasher: decompressed sha256 of base/dex/classes*.dex + base/lib/<abi>/*.so  (keyed to installed entry names)
      signerCertSha256 = uploadCert ∪ playSigningCertSha256
      Fingerprint{bundleMode=true, entries={}, bundleEntryHashes=...}  -> encode v3 -> seed‖XOR(...)
      inject base/assets/.../fingerprint.bin (STORED) ; AabSigner re-signs .aab

RUNTIME (det integrity, bundle blob):
  decode fingerprint -> bundleMode=true
    signer: every observed base.apk cert ∈ signerCertSha256 ? else apk_signer_mismatch (CRIT)
    entries: for name in bundleEntryHashes:
               h = first non-null over [sourceDir] + splitSourceDirs of apkEntryDecompressedHash(path, name)
               h == null -> apk_entry_removed (HIGH); h != baked -> apk_entry_modified (CRIT)
    sourceDir startswith /data/app/ ? else (existing finding)
```

## Testing / verification

- **Plugin unit tests:** `FingerprintCodec` v3 round-trip (bundleMode + bundleEntryHashes
  survive encode→decode; a v2 blob still decodes with defaults); `AabHasher` key
  normalization (`base/dex/classes.dex`→`classes.dex`, `base/lib/arm64-v8a/x.so`→`lib/arm64-v8a/x.so`)
  and decompressed-hash equals the inflated bytes' SHA-256 on a synthetic zip.
- **Native test (host, NDK clang):** `hash_entry_decompressed` over a small crafted zip with
  one STORED and one DEFLATED entry equals the SHA-256 of the decompressed payload; a missing
  entry → not-found; a truncated/garbage deflate stream → not-found (no crash, bounds-safe).
- **Device validation (clean device):** build the sample as an `.aab`, `bundletool build-apks
  --local-testing` (or `--mode=universal`) then `install-apks` to the device (local install
  uses the **upload key**, which is in the allow-set), launch → integrity must report **no**
  `fingerprint_asset_missing` / `apk_signer_mismatch` / `apk_entry_modified` (zero false
  positives). Then a **tamper test**: patch a baked `.so`/dex in a split (or flip one baked
  hash via a throwaway) → confirm `apk_entry_modified` CRITICAL fires.

## Migration / compatibility

- Schema v3 is **additive**; `MIN_SUPPORTED_FORMAT_VERSION` stays 1. Existing APK consumers
  (v1/v2 blobs) decode unchanged with `bundleMode=false` → the APK path is **byte-for-byte
  unchanged**. Bundle mode is **opt-in** (`appBundle.enabled=true`).
- `fingerprint_asset_missing` remains fail-open (a finding, not a crash), so a developer who
  enables bundle mode but mis-pins the Play cert gets a visible finding, never a hard failure.

## Residuals / non-goals (v1)

- Resources/manifest not byte-pinned in bundle mode (covered transitively by the signer pin).
- A kernel-level `/proc`/file MITM is out of scope (as for all of DI).
- No `apk_entry_added` detection in bundle mode (splits carry legitimate extra entries).
- bundletool is **not** added as a dependency; AAB re-sign uses the JDK `JarSigner`.

## Reference implementation (mirror, adapt to DI layout)

RASP source to mirror (in `/home/joseph/AndroidStudioProjects/DeviceIntelligenceRASP`):
`deviceintelligence-gradle/.../internal/AppBundleOptions.kt`, `internal/AabHasher.kt`,
`internal/AabSigner.kt`, `tasks/BundleFingerprintBuilder.kt`, `tasks/BundleIntegrityTask.kt`,
and the native bundle branch `deviceintelligence/src/main/cpp/dicore/detectors/apk/apk_verdict.cpp:139-188`
(adapt: RASP does the decision in native with vendored `tinfl`; **DI does the decision in
Kotlin and inflates via NDK zlib** per Option A).
