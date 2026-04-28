# DeviceIntelligence sample APKs

Two builds of the `samples:minimal` app, intended to be installed
side by side on an emulator (one at a time — they share the same
`applicationId` of `io.ssemaj.sample`).

## `minimal-genuine.apk`

The instrumented sample APK as the DeviceIntelligence Gradle plugin
produced it. Signed with the local Android debug keystore.
`F10.apk_integrity` sees the runtime cert match the baked
fingerprint, runs cleanly, and reports an empty `findings` list.

| Field | Value |
|-------|-------|
| Signer DN | `C=US, O=Android, CN=Android Debug` |
| Signer cert SHA-256 | `a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4` |
| Signing schemes | v2 + v3 |
| applicationId | `io.ssemaj.sample` |

Install:

```sh
adb install -r dist/minimal-genuine.apk
```

## `minimal-farm-resigned.apk`

Simulation of an "emulator farm" or sideload-rehost scenario. Built
by:

1. Taking `minimal-genuine.apk` byte-for-byte.
2. Stripping its `META-INF/` (drops original v1 + the original v2/v3
   blocks via re-sign).
3. `zipalign -p 4` to keep `.so` page-alignment intact.
4. Re-signing with `samples/minimal/keystore/fake.jks` (password
   `fakepass123`) using v1 + v2 + v3 schemes.

Everything else — code, native libs, assets including the baked
fingerprint blob — is identical. `F10.apk_integrity` sees the new
signer cert, compares against the baked one, and emits a finding
with `kind="apk_signer_mismatch"` and `severity="critical"`. F12
(emulator probe) and F13 (cloner probe) are signature-agnostic and
continue to operate normally on top of that.

| Field | Value |
|-------|-------|
| Signer DN | `CN=Fake Repackager, OU=Evil, O=Attacker, L=Nowhere, ST=NA, C=ZZ` |
| Signer cert SHA-256 | `98ab45b7278ad8011783b8cdd5e3a62a06ce2d7498755150fae61bc146782a0b` |
| Signing schemes | v1 + v2 + v3 |
| applicationId | `io.ssemaj.sample` |

Install:

```sh
adb uninstall io.ssemaj.sample            # different signer; can't update in place
adb install dist/minimal-farm-resigned.apk
```

## Rebuilding

`minimal-genuine.apk` is a copy of the AGP build artifact:

```sh
./gradlew :samples:minimal:assembleDebug
cp samples/minimal/build/outputs/apk/debug/minimal-debug.apk \
   dist/minimal-genuine.apk
```

`minimal-farm-resigned.apk` is regenerated from the genuine build
with the script-equivalent below (uses tools from
`$ANDROID_HOME/build-tools/<latest>/`):

```sh
WORK=$(mktemp -d)
cp dist/minimal-genuine.apk "$WORK/orig.apk"
( cd "$WORK" && zip -d orig.apk 'META-INF/*' )
zipalign -p -f 4 "$WORK/orig.apk" "$WORK/aligned.apk"
apksigner sign \
  --ks samples/minimal/keystore/fake.jks \
  --ks-pass pass:fakepass123 \
  --key-pass pass:fakepass123 \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out dist/minimal-farm-resigned.apk \
  "$WORK/aligned.apk"
```
