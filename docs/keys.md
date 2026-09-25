# Keys & licences

One X25519 keypair per app. Generate it on your machine — never in a build, never on a device:

```sh
python3 tools/keys/gen-dev-licence.py <applicationId> <out-dir>
```

That produces two files from one keypair:

| File | What it is | Where it goes |
|---|---|---|
| `server.key` (144 bytes) | The public half plus your licence: an `RVN2` blob carrying the X25519 public key, a SHA-256 hash of your `applicationId`, an expiry timestamp, and the epoch — all signed by the SDK publisher key. | Shipped in the APK at `assets/tech.thessemaj.deviceintelligence/server.key`. That exact path is where the runtime looks. |
| `server-priv-<epoch>.pem` | The X25519 private half. | Your backend only. It decrypts every token the device emits; anyone holding it can read tokens, so it never ships. |

What each side does with them:

- The device **encrypts every token to `server.key`** — only your backend private key opens it.
- `initialize()` **validates the licence** inside the same file: right package, not expired. A repackaged APK (different signer or id) fails this check at startup and reports `INTEL_0038`.
- The **epoch** (0–255) is a rotation counter: bump it, regenerate, ship the new `server.key` — and keep the old private PEMs around to decrypt tokens still in flight.
- `--not-after <epoch-seconds>` sets an optional expiry; `0` means never.

Dev vs release: the script signs with a publisher key compiled into the SDK, which is public by assumption — fine for development and the sample. For release builds, mint your key material with the `deviceintelligenceGenerateKey` Gradle task and keep the publisher key in your release pipeline instead.
