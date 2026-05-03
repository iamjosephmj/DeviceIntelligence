# Security policy

DeviceIntelligence is a security-telemetry library. Vulnerabilities in this code base affect every consumer app that integrates it; we treat reports seriously and respond promptly.

## Reporting a vulnerability

**Please do NOT file public GitHub issues for security reports.** A public issue makes the vulnerability addressable to attackers before downstream consumers can patch.

Email vulnerability reports to: **iamjosephmj@gmail.com**

Include in the report:

1. **Affected version(s)** — which DeviceIntelligence release(s) reproduce the issue. Tag-based version (`0.9.0`, `1.0.0`) and/or commit SHA.
2. **Affected detector(s) / component(s)** — `integrity.apk`, `integrity.art`, `runtime.environment` Vector A, native `.text` SHA-256 baseline, etc.
3. **Reproduction steps** — minimal sequence that demonstrates the issue. If a Frida script / LSPosed module / Magisk module is needed, include it.
4. **Impact assessment** — false-negative (failure to detect a real attack), false-positive (firing on a clean device), crash / DOS, information disclosure, etc.
5. **Suggested remediation** if you have one. Not required, but accelerates the fix.

Please do **not** include personally-identifying information about end users, real device fingerprints, or any consumer app's signing certificate hash in the report — synthetic / scrubbed reproduction data is sufficient.

## Response timelines

These are commitments, not best-efforts:

| Stage | SLO from initial report |
| --- | --- |
| Acknowledgement of receipt | within 72 hours |
| Initial impact triage | within 7 days |
| Fix or detailed mitigation plan | within 30 days for high/critical, 90 days for low/medium |
| Public disclosure (coordinated) | after a fix is released; researchers are credited unless they request anonymity |

If the SLO slips, we will tell you why before the deadline. Slipping silently is the failure mode we're committing not to.

## Supported versions

Security fixes are backported to the most recent **minor** release on the current major version. Pre-1.0 releases (`0.x.y`) are end-of-lifed once `1.0.0` ships.

| Version | Status |
| --- | --- |
| `1.0.x` | Supported — security fixes backported |
| `0.9.x` | End of life on `1.0.0` release |
| `0.8.x` and earlier | End of life — please upgrade |

## Scope

The following are **in scope**:

- Code in this repository (Kotlin runtime in `deviceintelligence/`, native C++ in `deviceintelligence/src/main/cpp/`, Gradle plugin in `deviceintelligence-gradle/`).
- Wire-format issues in `TelemetryReport.toJson()` / `SessionFindings.toJson()` output (e.g. injection through a `Finding.message` or `Finding.details` value, JSON parsing ambiguity).
- Cryptographic correctness of the analytics `client_id` derivation (SHA-256 of `ro.build.fingerprint`).
- Privacy regressions — any change that causes the wire format to leak PII or app-specific data that the analytics-opt-out documentation says is excluded.

The following are **out of scope**:

- Consumer apps that integrate DeviceIntelligence — we cannot triage your app's security issues, only the SDK's. Please use the consumer app's own disclosure channel.
- The behaviour of detection on a *specific* device (e.g. "Detector X reports `INCONCLUSIVE` on my Honor Magic5"). That's a coverage gap, not a vulnerability — please file a regular GitHub issue with reproduction steps.
- Third-party Frida / Xposed / LSPosed modules / etc., except where they exploit a specific bypass in DeviceIntelligence's detection logic. The CTF-roadmap framework already tracks bypass-targeted detection improvements; please file enhancement-style issues there for non-vulnerability evasion reports.

## Out-of-scope but interesting

If you find a way to evade detection that is *not* a bug in our code (a novel hooking framework, a kernel-level technique, a TEE compromise route), we'd love to hear about it. Email the same address with subject prefix `[evasion]` instead of `[vuln]`. We won't publish without your permission, won't run a CVE process for it, and we'll credit you in the relevant CTF roadmap entry if/when we ship detection.

## Coordinated disclosure preferences

We prefer **coordinated disclosure** over zero-day publication: report privately, give us the SLO above to fix, then publish jointly. We'll credit you in the release notes and the CHANGELOG entry that ships the fix unless you request anonymity.

For researchers planning a paper or conference talk: please contact us at least 90 days before the publication date so the fix has time to propagate to consumer apps.
