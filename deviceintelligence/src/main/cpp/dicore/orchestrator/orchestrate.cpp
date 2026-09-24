// orchestrate.cpp — the native detection -> verdict -> encrypted-token pipeline.
//
// Native is the orchestrator; the JVM (tech.thessemaj.deviceintelligence.dx.NativeBridge) is a thin shim. This
// library is DETECTION-ONLY: there is no enforcement/kill. The JNI entry points
// are the attest-once pair — `nat_enroll` (NativeBridge.e / initialize: attest once) and
// `nat_challenge` (NativeBridge.c / challenge: cheap per-request runtime sweep + sign). Both
// share `dicore_verdict`, which:
//
//   1. runs every verdict core (the *_records() functions, listed explicitly in
//      dicore_verdict) plus the count-only native-integrity / ART cores,
//   2. aggregates all findings into the plaintext verdict string,
//   3. hands them back so the caller can encrypt the token (encrypt_to_hex).
// (Hardware attestation runs only at enroll, not on the per-request challenge.)
//
// The token wraps a compact JSON signed_content (schemaVersion 2): the device
// reports raw signals as OPAQUE codes {"id":"INTEL_xxxx","severity","detail"} and
// the backend decides. detector/kind never leave the device — signal_to_json maps
// them to the wire code via signal_ids.gen.h (generated from signals-registry.json).
// Internally each finding is still a raw line "<detector> FS <kind> FS <severity>
// FS <detail>"; the (detector,kind)->id lookup happens at serialization only.
//
// Token crypto (v1, symmetric — see encrypt_to_hex): key = SHA256(phrase);
// keystream[i] = SHA256(key || u32le(i)); cipher = plain XOR ks; token = hex.
// Same framing as crl.bin, so the server decrypts with the same keystream.
//
// Fail-open invariant: a core that can't read its inputs contributes nothing —
// only an affirmative finding is recorded. Adding/removing a detector touches
// the dicore_verdict list below, not the callers.

#include "dicore/orchestrator/counters.h"
#include "dicore/orchestrator/licence_cache.h"
#include "dicore/orchestrator/lifecycle.h"
#include "dicore/orchestrator/custody_wd.h"
#include "dicore/orchestrator/orch_log.h"
#include "dicore/orchestrator/record_util.h"
#include "dicore/orchestrator/signal_ids.gen.h"

#include "dicore/core/verdict_cores.h"
#include "dicore/crypto/fp_pepper.h"
#include "dicore/crypto/licence_blob.h"
#include "dicore/crypto/sha256.h"
#include "dicore/crypto/token_crypto.h"
#include "dicore/detectors/native_integrity/system_libs/libart_verify.h"
#include "dicore/detectors/native_integrity/self/text_verify.h"
#include "dicore/jni/jni_anchors.h"
#include "dicore/jni/jni_cache.hpp"
#include "dicore/platform/framework_shim.h"
#include "dicore/platform/syscalls.h"

#include <android/api-level.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include "dicore/platform/obf.h"

#include <jni.h>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <cstring>
#include <mutex>
#include <ctime>
#include <string>
#include <vector>

// v2 token crypto is OPT-IN: build with -DDICORE_TOKEN_V2=1 (gradle -Pdeviceintelligence.tokenV2=1)
// to encrypt tokens as ECIES to the pinned server public key (server.key) instead
// of the v1 baked-phrase keystream. 0 (v1) by default until the fleet is on the
// dual-accept verifier and server.key ships (see the hybrid-encrypt spec §8 rollout).
#ifndef DICORE_TOKEN_V2
#define DICORE_TOKEN_V2 0
#endif

namespace dicore {


// Run every verdict core and count CRITICAL findings. Detection-only: no
// enforcement. The verdict is returned to the caller (see dicore_verdict below);
// nothing is killed. (Hardware attestation is verified BACKEND-side in :verifier,
// not here.)
// ---------------------------------------------------------------------------
// device-intelligence-lab — the single verdict entry point.
//
// Runs every detector once and returns the whole verdict as one string. Format:
//   line 0 : "VERDICT" FS "critical=<N>" FS "clean=<0|1>"
//   line k : "<detector>" FS "<kind>" FS "<severity>" FS <detector-specific...>
// (FS = 0x1f). The 7 record-emitting detectors contribute their findings
// verbatim (prefixed with the detector name); native-integrity and ART
// currently contribute a single CRITICAL summary record with
// a count — their per-finding kinds are in logcat (ORCH_LOG) and promoting them
// to full records is the next iteration. Everything fails open: a detector that
// cannot read its inputs contributes nothing.
namespace {
void append(std::vector<std::string>& out, const char* det,
            const std::vector<std::string>& recs, int& critical) {
    for (const auto& r : recs) {
        // __meta/__status are on-device metadata (e.g. the build-baked .text hash,
        // consumed before this call) — they are NOT findings, so they neither count
        // toward critical nor go on the wire (they have no signal code).
        if (r.empty() || r[0] == '_') continue;
        if (is_critical(r)) ++critical;
        out.push_back(std::string(det) + kFS + r);
    }
}

#if !DICORE_TOKEN_V2
// v1 token crypto: encrypt with a SHA-256 keystream keyed by a baked phrase and
// hex-encode. Identical framing to crl.bin (key = SHA256(phrase); keystream block
// i = SHA256(key || u32le(i)); cipher = plain XOR keystream), so the server side
// derives the same key from the phrase and decrypts with the existing tooling.
// This is symmetric (tamper-resistance + confidentiality in transit, not
// unforgeability); the hardened model — hybrid-encrypt to the server public key +
// bind to the hardware-attestation challenge — is the next iteration.
constexpr char kTokenPhrase[] = "intel-verdict-token-key-v1";

std::string encrypt_to_hex(const std::string& plain) {
    uint8_t key[32];
    sha::sha256(kTokenPhrase, sizeof(kTokenPhrase) - 1, key);
    std::vector<uint8_t> buf(plain.begin(), plain.end());
    uint8_t in[36];
    std::memcpy(in, key, 32);
    uint8_t ks[32];
    uint32_t block = 0;
    for (size_t off = 0; off < buf.size(); off += 32, ++block) {
        in[32] = (uint8_t)(block);       in[33] = (uint8_t)(block >> 8);
        in[34] = (uint8_t)(block >> 16);  in[35] = (uint8_t)(block >> 24);
        sha::sha256(in, sizeof(in), ks);
        for (size_t i = 0; i < 32 && off + i < buf.size(); ++i) buf[off + i] ^= ks[i];
    }
    static const char hexd[] = "0123456789abcdef";
    std::string out;
    out.reserve(buf.size() * 2);
    for (uint8_t b : buf) { out.push_back(hexd[(b >> 4) & 0xf]); out.push_back(hexd[b & 0xf]); }
    return out;
}
#endif  // !DICORE_TOKEN_V2

// Both are defined further down but are needed by licence()'s fingerprint build.
std::string json_escape(const std::string& s);
std::string dicore_prop_get(const char* name);

// ---- Licence state ---------------------------------------------------------
// Evaluated ONCE per process and shared by every consumer, so there is exactly one
// answer to "is this build licensed" and exactly one parse of the blob.
//
// This is a FAIL-FAST against lifting the .so plus assets into another APK, NOT a
// security control: an attacker who has patched this core has patched this check
// with it. The enforcing licence check is backend-side, on the app identity the TEE
// attested (tag 709). Nothing may be sold on this.
struct Licence {
    dicore::crypto::LicenceKey key;
    bool ok;
    // The blob parsed, so key holds a usable server public key EVEN IF ok is false
    // (expired / bound to another package). That is what lets a degraded token be
    // encrypted at all — see the degraded-token design, section 1.
    bool parsed = false;
    dicore::LicenceReason reason = dicore::LicenceReason::OK;
    std::string fp_json;   // the "fp" object body, or empty when unavailable
    std::string fp_hash;   // hex sha256 of fp_json, or empty
};

static const Licence& licence() {
    // Evaluated once, but only a CONCLUSIVE answer is cached — see licence_cache.h.
    // The former magic static cached whatever the first call produced, and calls
    // that landed before NativeBridge.s() registered the framework shim read "" for both the
    // asset and the package name, manufacturing a permanent "package mismatch"
    // that initialize() could never recover from. An evaluation with nothing to
    // judge now returns a not-ok answer WITHOUT caching it, so the first call that
    // can actually read the framework settles it.
    static std::mutex mu;
    static std::atomic<const Licence*> cached{nullptr};
    // The "ask again" answer: not licensed, nothing published, never cached.
    static const Licence kDeferred{};

    if (const Licence* p = cached.load(std::memory_order_acquire)) return *p;

    std::lock_guard<std::mutex> lk(mu);
    if (const Licence* p = cached.load(std::memory_order_relaxed)) return *p;

    Licence out{};
    out.ok = false;
    dicore::LicenceInputs in{};

    std::vector<uint8_t> raw = fw_licence_asset();
    in.asset_readable = !raw.empty();
    in.parsed = in.asset_readable &&
        dicore::crypto::licence_blob_parse(raw.data(), raw.size(), &out.key);
    in.expired = in.parsed && out.key.not_after != 0 &&
        (uint64_t) time(nullptr) > out.key.not_after;

    // RVN1 blobs carry no package binding (all-zero pkg_hash): an unbound blob is
    // not a mismatched one, so there is nothing to compare.
    if (in.parsed) {
        for (int i = 0; i < 32; ++i) if (out.key.pkg_hash[i] != 0) { in.bound = true; break; }
        if (in.bound) {
            const std::string pkg = fw_package_name();
            // Not just non-empty: a forked process is still called "zygote64" until
            // ActivityThread renames it, and hashing THAT produced a conclusive
            // package mismatch that got cached for the life of the process. See
            // pkg_name_is_settled — measured under an Xposed framework, whose module
            // loading runs at fork time and triggered exactly that.
            in.pkg_readable = dicore::pkg_name_is_settled(pkg);
            uint8_t want[32];
            if (in.pkg_readable &&
                dicore::sha::sha256(reinterpret_cast<const uint8_t*>(pkg.data()),
                                       pkg.size(), want)) {
                uint8_t diff = 0;
                for (int i = 0; i < 32; ++i)
                    diff |= static_cast<uint8_t>(want[i] ^ out.key.pkg_hash[i]);
                in.pkg_matches = (diff == 0);
            }
        }
    }

    const dicore::LicenceEval eval = dicore::licence_evaluate(in);
    out.parsed = in.parsed;
    out.reason = dicore::licence_reason(in);
    if (!dicore::licence_should_cache(eval)) return kDeferred;

    if (eval == dicore::LicenceEval::VALID) {
        // ---- Device fingerprint -------------------------------------------------
        // Built ONCE here and cached for the process: MediaDrm costs real
        // milliseconds and initialize() is already off the request path.
        uint8_t pepper[32];
        dicore::crypto::fp_pepper(out.key, pepper);

        // JVM-only fields: widevineId, widevineLevel, androidId.
        std::string fpRaw = fw_fingerprint_raw();
        std::string f[3];
        for (int i = 0, start = 0; i < 3; ++i) {
            size_t nl = fpRaw.find('\n', (size_t)start);
            f[i] = fpRaw.substr((size_t)start,
                              nl == std::string::npos ? std::string::npos : nl - (size_t)start);
            if (nl == std::string::npos) break;
            start = (int)nl + 1;
        }
        std::string idHash, aidHash;
        dicore::crypto::fp_hash(pepper, f[0], &idHash);   // stays empty if input is empty
        dicore::crypto::fp_hash(pepper, f[2], &aidHash);

        // Native fields. These feed INTEL_0048, so they are deliberately NOT read
        // through the JVM: a prop spoofer hooking FrameworkShim.q must not be able
        // to forge the evidence that catches it. A native property hook is still
        // possible but is already covered by INTEL_0043.
        std::string kernel;
        {
            struct utsname u {};
            int err = 0;
            if (dicore::sys::raw_uname(&u, &err) == 0) kernel = u.release;
        }

        out.fp_json = std::string("{\"id\":\"") + json_escape(idHash) +
            "\",\"aid\":\"" + json_escape(aidHash) +
            "\",\"lvl\":\"" + json_escape(f[1]) +
            "\",\"build\":\"" + json_escape(dicore_prop_get("ro.build.fingerprint")) +
            "\",\"kernel\":\"" + json_escape(kernel) +
            "\",\"patch\":\"" + json_escape(dicore_prop_get("ro.build.version.security_patch")) +
            "\",\"installer\":\"" + json_escape(fw_installer_package()) + "\"}";

        uint8_t d[32];
        if (dicore::sha::sha256(reinterpret_cast<const uint8_t*>(out.fp_json.data()),
                                   out.fp_json.size(), d)) {
            static const char* hexd = "0123456789abcdef";
            out.fp_hash.reserve(64);
            for (uint8_t b : d) {
                out.fp_hash.push_back(hexd[(b >> 4) & 0xf]);
                out.fp_hash.push_back(hexd[b & 0xf]);
            }
        }

        out.ok = true;
    }

    // Published once and never mutated, so the reference every caller holds stays
    // valid and immutable for the life of the process. Deliberately leaked: it
    // outlives every consumer by construction.
    const Licence* pub = new Licence(std::move(out));
    cached.store(pub, std::memory_order_release);
    return *pub;
}

// Token encoder — routed by build flavor. v1: symmetric keystream (encrypt_to_hex).
// v2 (-DDICORE_TOKEN_V2=1): ECIES to the pinned server public key in server.key.
// FAIL-CLOSED in v2: any missing/invalid server.key or crypto error yields an EMPTY token
// (never a v1 fallback) so the backend rejects rather than accepting a weaker envelope.
#if DICORE_TOKEN_V2
std::string token_encode(const std::string& plain) {
    // Gated on PARSED, not on ok: a blob that parsed carries a usable server public
    // key even when the licence itself is rejected (expired, or bound to another
    // package). Those cases now emit a DEGRADED token that names the rejection
    // rather than silence, because silence is what an attacker wants — see the
    // degraded-token design. A blob that did not parse has no key to encrypt to, so
    // that case still yields "" and is the one unavoidable silence.
    //
    // Never a v1 fallback: the backend refuses a v1 token outright, so a weaker
    // envelope would be rejected rather than accepted.
    const Licence& l = licence();
    if (!l.parsed) return std::string();
    std::string out;
    if (!dicore::crypto::dicore_token_encrypt(plain, l.key, &out)) return std::string();
    return out;
}
#else
std::string token_encode(const std::string& plain) { return encrypt_to_hex(plain); }
#endif

// Read a system property (self-report). Used to include the OS-claimed boot state
// in the enroll bundle so the backend can cross-check it against the hardware
// attestation RootOfTrust — any prop-spoofing Play-Integrity-Fix makes these lie
// while the TEE attestation reports the truth (see EnrollVerifier boot-state gate).
std::string dicore_prop_get(const char* name) {
    char v[PROP_VALUE_MAX] = {0};
    int n = __system_property_get(name, v);
    return n > 0 ? std::string(v, (size_t)n) : std::string();
}

std::string to_hex(const std::vector<uint8_t>& v) {
    static const char hexd[] = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v) { out.push_back(hexd[(b >> 4) & 0xf]); out.push_back(hexd[b & 0xf]); }
    return out;
}

// B1: the token path's string marshalling rides the JNI_OnLoad vtable
// snapshot (captured before anchor registration can even run), so a vtable
// patched after load cannot interpose what the scan reads or emits. The
// never-captured fallback (impossible past JNI_OnLoad) keeps the old live
// -table behaviour — fail-open, never a silent empty token.
std::string jstr(JNIEnv* env, jstring j) {
    if (j == nullptr) return "";
    const jni_cache::Cache& jc = jni_cache::static_cache();
    auto chars = jni_cache::get<jni_cache::Slot::GetStringUTFChars,
                                jni_cache::getstringutfchars_fn>(jc);
    auto release = jni_cache::get<jni_cache::Slot::ReleaseStringUTFChars,
                                  jni_cache::releasestringutfchars_fn>(jc);
    const char* p = chars ? chars(env, j, nullptr)
                          : env->GetStringUTFChars(j, nullptr);
    std::string s = p ? p : "";
    if (p) {
        if (release) release(env, j, p);
        else env->ReleaseStringUTFChars(j, p);
    }
    return s;
}

// Same snapshot ride for the string emissions (nat_enroll / nat_challenge
// return values). A late hook on NewStringUTF can no longer swap what the
// app receives; Vector C also watches the slot for any unwired caller.
jstring new_string_utf(JNIEnv* env, const char* s) {
    const jni_cache::Cache& jc = jni_cache::static_cache();
    auto fn = jni_cache::get<jni_cache::Slot::NewStringUTF,
                             jni_cache::newstringutf_fn>(jc);
    return fn ? fn(env, s) : env->NewStringUTF(s);
}

// Minimal JSON string escaping (", \, and control chars).
std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    static const char kH[] = "0123456789abcdef";
                    o += "\\u00"; o += kH[(c >> 4) & 0xf]; o += kH[c & 0xf];
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

// One raw signal line ("<detector>\x1f<kind>\x1f<severity>\x1f<detail...>") to a
// JSON object. Missing fields become empty; detail joins any remaining fields.
std::string signal_to_json(const std::string& line) {
    std::string parts[3];
    std::string detail;
    size_t start = 0;
    int idx = 0;
    for (size_t i = 0; i <= line.size(); ++i) {
        if (i == line.size() || line[i] == kFS) {
            std::string tok = line.substr(start, i - start);
            if (idx < 3) parts[idx] = tok;
            else { if (!detail.empty()) detail += ' '; detail += tok; }
            ++idx;
            start = i + 1;
        }
    }
    // The wire carries ONLY the opaque registry code — detector/kind never leave
    // the device (real abstraction; the backend resolves id via signals-registry.json).
    const char* id = dicore::signal_id(parts[0], parts[1]);
    return std::string("{\"id\":\"") + id +
           "\",\"severity\":\"" + json_escape(parts[2]) +
           "\",\"detail\":\"" + json_escape(detail) + "\"}";
}
}  // namespace

DI_OBF_ORCH
// Runs every detector and returns the RAW signal lines
// ("<detector>\x1f<kind>\x1f<severity>\x1f<detail>"). It no longer decides
// clean/critical — that judgment moved to the backend (see the challenge JSON payload
// + tools/server/verify_token.py). `critical` is still counted, but ONLY to drive
// the on_clean_device() string-unlock gate; it is not emitted as authority.
std::vector<std::string> dicore_verdict(JNIEnv* env) {
    std::vector<std::string> out;
    int critical = 0;

    // Custody watchdog: fork the key-holding child before the sweep runs so
    // its beat loop is alive when the clean-sweep bit latches (see
    // custody_wd.h). Idempotent.
    custody_wd_init();

    // APK first — its __meta row carries the build-baked .text hash that G2
    // (native-integrity) compares against, so it must be read before det_native.
    //
    // RATE-LIMITED. Hashing the whole APK is by far the most expensive core (~140ms
    // on a Pixel 6 Pro, ~55% of the sweep) and it re-read the file on EVERY scan. The
    // result can only change if base.apk changes on disk, which Android does not allow
    // under a live process — a legitimate update kills it. The one case re-reading
    // catches is a ROOT-level on-disk swap while the process keeps its old mapping, so
    // this is rate-limited rather than cached outright: the detection survives, bounded
    // by kApkRecheckMs, and back-to-back scans stop paying for it.
    {
        static std::mutex apk_mu;
        static std::vector<std::string> apk_cache;
        static std::chrono::steady_clock::time_point apk_at{};
        static bool apk_have = false;
        constexpr long long kApkRecheckMs = 60'000;   // re-hash at most once a minute

        std::lock_guard<std::mutex> lk(apk_mu);
        const auto now = std::chrono::steady_clock::now();
        const bool stale = !apk_have ||
            std::chrono::duration_cast<std::chrono::milliseconds>(now - apk_at).count() >= kApkRecheckMs;
        if (stale) {
            apk_cache = apk_verdict_records(fw_source_dir(), fw_fingerprint_asset(),
                                            fw_installer_package(), fw_primary_abi());
            apk_at = now;
            apk_have = true;
        }
        const auto& recs = apk_cache;
        for (const auto& r : recs) {
            if (r.rfind("__meta", 0) == 0) {
                std::string textHash = field(r, 4);
                if (!textHash.empty())
                    native_integrity::set_expected_text_hash(textHash.c_str());
                break;
            }
        }
        append(out, "apk", recs, critical);
    }

    // Count-only cores (per-finding detail in logcat for now) -> summary records.
    if (int n = count_native_integrity_critical(); n > 0) {
        critical += n;
        out.push_back(std::string("native") + kFS + "native_integrity_critical" +
                      kFS + "CRITICAL" + kFS + "count=" + std::to_string(n));
    }
    // G10 — libart .text vs the on-disk file. Emits per-site records with the
    // patch offset and bytes, so a hook inside ART's own code is reported with
    // evidence rather than as a count.
    append(out, "native", native_integrity::libart_verdict_records(), critical);
    append(out, "self_hook", prologue_verdict_records(), critical);
    if (int n = env ? count_art_hook_critical(env) : 0; n > 0) {
        critical += n;
        out.push_back(std::string("art") + kFS + "art_hook_critical" +
                      kFS + "CRITICAL" + kFS + "count=" + std::to_string(n));
    }
    // cloner REMOVED from the verdict (false-positive prone): work profiles and
    // dual-app (Samsung Dual Messenger, Xiaomi Dual Apps, Island, Shelter) are
    // legitimate and common, especially for enterprise users — the cloner signals
    // fire on them. An actual malicious clone is inferred server-side instead.
    append(out, "dex", dex_provenance_records(), critical);
    append(out, "root", root_verdict_records(), critical);
    // emulator — the CPU-identity probes stay OFF the wire (issue #8): the x86
    // CPUID hypervisor bit is set on genuine ChromeOS (ARCVM) / WSA, and the
    // arm64 CNTFRQ check is heuristic. INTEL_0056 translated_environment IS wired:
    // uname-vs-ABI divergence is definitional (an arm64 process on an x86 kernel
    // cannot happen on silicon) and the native-bridge sub-facts only fire on
    // images that ship a translation layer — raw-syscall reads, fail-open, so
    // they clear the FP bar the CPU probes failed.
    append(out, "emulator", emu_translation_records(), critical);
    // INTEL_0061 — cpu_rerouting_anomaly: behavioural companion to INTEL_0056.
    // Both sub-facts (CNTVCT-off-CNTFRQ rate, UDF fault replayed as a
    // user-sent signal) are architecturally impossible on genuine silicon,
    // so this clears the same FP bar that kept the CPUID/CNTFRQ-value probes
    // off the wire — and it still fires when a bridge renames itself out of
    // INTEL_0056's provenance keys. Fail-open; arm64-only.
    append(out, "emulator", emu_rerouting_records(), critical);
    // INTEL_0062 — hypervisor_cpu: the x86_64 CPU-state probe (CPUID
    // hypervisor bit + vendor leaf) for hardware-virtualized emulators,
    // where nothing is translated and INTEL_0056 correctly stays silent.
    // Real-phone silicon cannot set the bit; x86_64 Android also runs on
    // Chromebooks/WSA (also set) — severity reflects that honestly.
    append(out, "emulator", emu_hv_records(), critical);
    // INTEL_0063 — arm64_vm_platform: the arm64 tier-2 probe (device-tree
    // markers + qemu_pipe) for VMs and full-system emulators that run ARM
    // code natively inside an emulated ARM system — invisible to INTEL_0056
    // (guest ISA matches the app) and to INTEL_0062 (x86-only).
    append(out, "emulator", emu_vm_platform_records(), critical);
    append(out, "environment", antidebug_verdict_records(), critical);
    append(out, "seccomp", seccomp_verdict_records(), critical);
    // INTEL_0057 — anon/memfd/deleted executable mappings (zygisk stub pools,
    // Frida gadgets, unloaded payloads), read through the maps family's
    // raw-syscall reader. Fail-open like everything above.
    append(out, "environment", anon_exec_records(), critical);
    // INTEL_0058 — the scan channel's own sequence/rate invariant. Advances the
    // MAC chain at scan entry and trips on a synthetic-sweep rate; the (seq,
    // mac) pair rides the record as evidence for the backend replay check.
    append(out, "native_integrity", channel_guard_records(), critical);
    // INTEL_0059 — own executable segment vs the CMake-baked build digest
    // (dicore_text_digest_gen.h; all-zero = no baseline yet -> skipped).
    append(out, "native_integrity", text_digest_records(), critical);
    // INTEL_0060 — fork-exec watchdog child: an independent /system/bin/sh
    // loop reports the parent's TracerPid over a private pipe every beat
    // period; 3 missed beats (cause=silent) or a nonzero tracer report
    // (cause=tracer) emit one HIGH record with a keyed-heartbeat (seq, mac)
    // evidence pair. Fail-open, detection-only.
    append(out, "native_integrity", watchdog_records(), critical);

    if (critical == 0) on_clean_device();  // publish the string-unlock gate
    else custody_wd_note_critical();       // a CRITICAL sweep stops custody release

    ORCH_LOG("signals: on-device critical=%d (advisory only) count=%zu", critical, out.size());
    return out;
}

// ---- Attested-session cache ------------------------------------------------
// The TEE attestation is the one genuinely expensive call in the SDK (~150ms, and
// multiple seconds on devices backing StrongBox with a slow secure element), so it
// runs ONCE per session — at setSession(), off the request path — and every scan
// reads this. Process memory only: never persisted, so a cold start always
// re-attests against whatever session it is given.
//
// It cannot move any earlier than setSession(): the attestation challenge IS the
// session id, and that binding is what makes a captured scan useless against
// another session. initialize() has no session to bind to.
namespace {
struct AttestedSession {
    std::string session_id;
    std::vector<std::vector<uint8_t>> chain;               // [0]=spki, [1..]=certs
    std::vector<std::vector<std::vector<uint8_t>>> xlevel; // [0]=SB, [1]=TEE
    std::string attested_key;                              // hex spki
    bool valid = false;
    bool delivered = false;   // has a scan already carried the chain?
};

std::mutex g_session_mu;
AttestedSession g_session;
}  // namespace

// NativeBridge.initialize(): licence validation ONLY. Parses the licence blob, checks the
// publisher signature, the package binding and the expiry, and caches the server
// public key for the token envelope. No TEE call, no keystore entry, no network,
// no nonce — the attestation moved to the first scan, where a server-issued
// sessionId exists to bind it to. Returns "1" on success, "" on any failure.
//
// This is a FAIL-FAST, NOT a security control. An attacker who has patched this
// core has patched this check with it; its value is that it stops the .so plus
// assets being lifted into another APK without effort, and that it fails at
// startup rather than silently at request time. The enforcing licence check is
// backend-side, on the attested app identity (tag 709). Nothing is sold on this.
DI_OBF_ORCH
jstring JNICALL anchors::nat_enroll(JNIEnv* env, jclass, jstring challJ) {
    (void) challJ;   // reserved; the JNI ABI is fixed by RegisterNatives
    return new_string_utf(env, licence().ok ? "1" : "");
}

// K.setSession(): attest once for THIS session and cache the result.
//
// Idempotent — re-preparing the same session id is a no-op, so an app that sets the
// same session repeatedly pays for one keygen. A DIFFERENT id re-attests, because
// the old chain names the old session and the backend has no binding for it.
//
// Blocking and slow by design (a TEE/StrongBox keygen). Call it off the UI thread;
// that is the whole point of doing it here rather than on the first scan.
DI_OBF_ORCH
jboolean JNICALL anchors::nat_prepare(JNIEnv* env, jclass, jstring sidJ) {
    if (!licence().ok) return JNI_FALSE;
    std::string sid = jstr(env, sidJ);
    if (sid.empty()) return JNI_FALSE;

    std::lock_guard<std::mutex> lk(g_session_mu);
    if (g_session.valid && g_session.session_id == sid) return JNI_TRUE;   // already prepared

    const uint8_t* sidBytes = reinterpret_cast<const uint8_t*>(sid.data());
    auto chain = fw_session_keygen(sidBytes, sid.size());   // [spki, leaf, chain...]
    if (chain.empty()) {                                    // fail closed
        g_session = AttestedSession{};
        return JNI_FALSE;
    }

    g_session = AttestedSession{};
    g_session.session_id = sid;
    g_session.attested_key = to_hex(chain[0]);
    g_session.chain = std::move(chain);
    // Cross-level chains for the leaked-keybox forensics, attested to the same id.
    g_session.xlevel = fw_attest_chains_xlevel(sidBytes, sid.size());
    g_session.valid = true;
    g_session.delivered = false;
    return JNI_TRUE;
}

// K.scan(): the per-request call, and the only one that produces a token.
//
// BOOTSTRAP (first scan of a cold start): carries the CERT + XLEVEL_* chains that
// setSession() attested, bound to the app's server-issued sessionId. That binding
// is what makes a captured scan useless against any other session.
//
// STEADY-STATE (every later scan): runtime detectors only, signed with the key
// bootstrap attested. No attestation, no keystore work.
//
// FAILS LOUD, NOT OPEN. Every gate here — licence, session, attestation — is one a
// hook engine breaks first, and returning "" for them made SUPPRESSING the SDK
// cheaper than defeating it: silence at the backend is indistinguishable from a
// network error, an old SDK, or an app that never integrated. So a scan that
// cannot be bound still emits a token; the token names its own missing binding and
// carries the detector findings anyway. The one unavoidable silence is a licence
// blob that did not parse, because the server public key lives inside it and there
// is then nothing to encrypt to.
//
// A degraded token is NEVER evidence of a clean device: it is unauthenticated, so
// the backend grades it as compromised-equivalent and treats it as advisory.
DI_OBF_ORCH
jstring JNICALL anchors::nat_challenge(JNIEnv* env, jclass, jstring sidJ, jstring nameJ, jstring challJ) {
    // Launch the decoy-syscall smokescreen FIRST so it runs in parallel with the
    // scan below (fire-and-forget, detached; never feeds or blocks the verdict).
    dicore_launch_syscall_smoke();

    std::string sid = jstr(env, sidJ), name = jstr(env, nameJ), challHex = jstr(env, challJ);

    // ---- what this token can honestly claim about itself ---------------------
    // `level` describes the KEY, `signed` describes what actually signed THIS token;
    // they degrade independently (a hooked keygen gives level=NONE, signed=SOFTWARE;
    // a healthy device that lost its Keystore mid-session gives the reverse).
    //
    // `level` deliberately does NOT claim StrongBox vs TEE. The device cannot tell
    // them apart without parsing its own chain, and the backend derives the real
    // assurance from the certificate — which is authoritative and unforgeable. A
    // device-side claim would be redundant where it agrees and a lie where it does not.
    const char* att_level = "NONE";       // ATTESTED | SOFTWARE | NONE
    const char* att_reason = "OK";
    std::string att_detail;

    const Licence& lic = licence();
    if (!lic.ok) {
        switch (lic.reason) {
            case dicore::LicenceReason::EXPIRED:      att_reason = "LICENCE_EXPIRED"; break;
            case dicore::LicenceReason::PKG_MISMATCH: att_reason = "LICENCE_PKG_MISMATCH"; break;
            default:                                     att_reason = "LICENCE_UNPARSEABLE"; break;
        }
    }

    // Read the cached attestation. NO TEE call here: setSession() did that once and
    // a scan only reads it. The FIRST scan of a session carries the chain.
    bool bootstrap = false;
    std::vector<std::vector<uint8_t>> session;
    std::vector<std::vector<std::vector<uint8_t>>> xlevel;
    std::string attestedKey;
    bool have_session = false;
    {
        std::lock_guard<std::mutex> lk(g_session_mu);
        have_session = g_session.valid && g_session.session_id == sid && !sid.empty();
        if (have_session) {
            bootstrap = !g_session.delivered;
            attestedKey = g_session.attested_key;
            if (bootstrap) {
                session = g_session.chain;
                xlevel = g_session.xlevel;
                g_session.delivered = true;
            }
        }
    }

    if (have_session) {
        att_level = "ATTESTED";
    } else if (sid.empty()) {
        if (att_reason[0] == 'O') att_reason = "NO_SESSION";   // don't mask a licence reason
    } else {
        if (att_reason[0] == 'O') att_reason = "KEYGEN_FAILED";
        att_detail = fw_last_keygen_error();
    }

    // ---- detectors run UNCONDITIONALLY --------------------------------------
    // They never touch the TEE, so they are INDEPENDENT evidence about this process:
    // a hook that broke the attestation almost always trips the ART/JNI, native
    // .text and libc-hook detectors, while a StrongBox that was never fitted trips
    // nothing. That difference is what lets the backend tell a device fault from an
    // injection, and it only exists because this runs before any gate.
    std::vector<std::string> signals = dicore_verdict(env);

    // The degradation itself is a finding, in the same taxonomy as everything else.
    // Record format is "<detector> FS <kind> FS <severity> FS <detail>" — the same
    // four fields every detector emits, so these resolve through signal_to_json and
    // the registry exactly like any other signal. Severity is a device HINT; the
    // backend reweights it from the registry.
    const std::string FS1 = "\x1f";
    if (!lic.ok)
        signals.push_back("attestation" + FS1 + "licence_rejected_at_scan" + FS1 + "high" +
                          FS1 + std::string("reason=") + att_reason);
    if (sid.empty())
        signals.push_back("attestation" + FS1 + "scan_without_session" + FS1 + "critical" +
                          FS1 + "setSession() was never called, failed, or named another session");
    else if (!have_session)
        signals.push_back("attestation" + FS1 + "session_attestation_unavailable" + FS1 + "critical" +
                          FS1 + (att_detail.empty() ? std::string("keygen failed or was hooked")
                                                    : std::string("keygen=") + att_detail));

    // ---- the SOFTWARE rung ---------------------------------------------------
    // Only when there is no attested key. Proves nothing about the device; it gives
    // the backend continuity across the degraded scans of one process.
    std::string fallbackKey;
    if (!have_session) {
        std::vector<uint8_t> spki = fw_fallback_key_spki();
        if (!spki.empty()) {
            fallbackKey = to_hex(spki);
            att_level = "SOFTWARE";
        }
    }

    // The rung is decided by which key EXISTS, so it is known before the document is
    // built — which is what lets the "nothing can sign" case be recorded as a signal
    // inside the signed content rather than bolted on afterwards.
    const char* rung = have_session ? "ATTESTED" : (fallbackKey.empty() ? "NONE" : "SOFTWARE");
    if (rung[0] == 'N')
        signals.push_back("attestation" + FS1 + "token_emitted_unsigned" + FS1 + "critical" +
                          FS1 + "no attested key and no software fallback key was available");

    std::string sigArr = "[";
    for (size_t i = 0; i < signals.size(); ++i) { if (i) sigArr += ","; sigArr += signal_to_json(signals[i]); }
    sigArr += "]";

    int api = android_get_device_api_level();
    DeviceIdentity id = fw_device_identity();

    std::string sc = std::string("{\"schemaVersion\":4,\"type\":\"scan\",\"sessionId\":\"") +
        json_escape(sid) + "\",\"name\":\"" + json_escape(name) +
        "\",\"ts\":" + std::to_string((long long)time(nullptr)) +
        ",\"bootstrap\":" + (bootstrap ? "true" : "false") +
        ",\"app\":{\"package\":\"" + json_escape(fw_package_name()) +
        "\",\"signer\":\"" + json_escape(fw_signing_digest()) + "\"}";
    if (bootstrap) sc += ",\"attestedKey\":\"" + json_escape(attestedKey) + "\"";
    if (!fallbackKey.empty()) sc += ",\"softwareKey\":\"" + json_escape(fallbackKey) + "\"";

    // Full fingerprint on the bootstrap scan; the digest alone on later scans. An OS
    // update cannot happen inside one session, so a changed digest means the device
    // changed under the session. A degraded scan carries the full one too — it is
    // never a "later scan" of an established session.
    if (bootstrap || !have_session) {
        if (!licence().fp_json.empty()) sc += ",\"fp\":" + licence().fp_json;
    } else {
        if (!licence().fp_hash.empty()) sc += ",\"fpHash\":\"" + licence().fp_hash + "\"";
    }
    if (!challHex.empty()) sc += ",\"nonce\":\"" + json_escape(challHex) + "\"";
    sc += ",\"device\":{\"api\":" + std::to_string(api) + ",\"abi\":\"" + json_escape(fw_primary_abi()) +
        "\",\"brand\":\"" + json_escape(id.ok ? id.brand : std::string()) +
        "\",\"device\":\"" + json_escape(id.ok ? id.device : std::string()) +
        "\",\"product\":\"" + json_escape(id.ok ? id.product : std::string()) +
        "\",\"manufacturer\":\"" + json_escape(id.ok ? id.manufacturer : std::string()) +
        "\",\"model\":\"" + json_escape(id.ok ? id.model : std::string()) +
        "\",\"vbs\":\"" + json_escape(dicore_prop_get("ro.boot.verifiedbootstate")) +
        "\",\"blocked\":\"" + json_escape(dicore_prop_get("ro.boot.flash.locked")) +
        "\",\"vbmeta\":\"" + json_escape(dicore_prop_get("ro.boot.vbmeta.device_state")) +
        "\",\"sbFeature\":\"" + json_escape(fw_strongbox_feature()) +
        "\"},\"signals\":" + sigArr;

    // ---- the signing ladder --------------------------------------------------
    // Attested session key -> plain Keystore key -> nothing. The rung is decided by
    // which key EXISTS, and stated in the document, so the backend never has to
    // infer it. The attestation block is part of the signed content, so on a signed
    // token it cannot be stripped or rewritten in transit.
    sc += std::string(",\"attestation\":{\"level\":\"") + att_level +
        "\",\"signed\":\"" + rung +
        "\",\"reason\":\"" + json_escape(att_reason) + "\"";
    if (!att_detail.empty()) sc += ",\"detail\":\"" + json_escape(att_detail) + "\"";
    sc += "}}";

    std::vector<uint8_t> sig;
    bool signed_ok = false;
    if (have_session)
        signed_ok = fw_session_sign(reinterpret_cast<const uint8_t*>(sc.data()), sc.size(), sig);
    else if (!fallbackKey.empty())
        signed_ok = fw_fallback_sign(reinterpret_cast<const uint8_t*>(sc.data()), sc.size(), sig);

    // A key that exists but fails to sign (a keystore that dies mid-call) leaves the
    // document claiming a rung it did not reach. The EMPTY SIG is authoritative
    // there: the backend reads the binding, not the claim, so an unverifiable token
    // is treated as unsigned whatever the document says. The claim is only ever
    // trustworthy on a token whose signature verifies — at which point it is signed.
    if (!signed_ok) sig.clear();

    // The binding section is ALWAYS present, with an empty SIG when nothing could
    // sign. "No binding at all" stays reserved for a genuinely malformed token, so
    // existing parsers keep their shape.
    std::string plain = sc;
    plain += std::string("\n--BINDING\nSIG") + "\x1f" + (sig.empty() ? std::string() : to_hex(sig));

    if (bootstrap) {
        // The attestation binding: the chain the backend verifies to a pinned root,
        // plus the cross-level chains for the keybox-reuse check. Both attested to
        // the same sessionId.
        for (size_t i = 1; i < session.size(); ++i)
            plain += std::string("\nCERT") + "\x1f" + to_hex(session[i]);
        if (xlevel.size() == 2) {
            for (auto& c : xlevel[0]) plain += std::string("\nXLEVEL_SB") + "\x1f" + to_hex(c);
            for (auto& c : xlevel[1]) plain += std::string("\nXLEVEL_TEE") + "\x1f" + to_hex(c);
        }
    }
    return new_string_utf(env, token_encode(plain).c_str());
}

}  // namespace dicore
