#include "dicore/platform/framework_shim.h"

#include "dicore/platform/log.h"
#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/jni/jni_anchors.h"
#include "dicore/jni/jni_cache.hpp"

#include "dicore/detectors/apk/container/apkmap.h"          // ApkMap
#include "dicore/detectors/apk/container/zip_parser.h"      // find_central_directory / read_entry_raw
#include "dicore/detectors/cloner/cloner_probe.h" // read_apk_path_from_maps

#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dicore {


namespace {

JavaVM* g_vm = nullptr;
// The framework-shim class, handed to us at bootstrap via NativeBridge.s(Class) and held as
// a global ref. We do NOT FindClass it by a literal name — that name is no longer
// fixed (R8 renames the shim), so caching the passed Class is the only binding.
jclass g_shim_cls = nullptr;

// RAII JNIEnv: reuse the current thread's env if attached, else attach + detach.
struct ScopedEnv {
    JNIEnv* env = nullptr;
    bool attached = false;
    ScopedEnv() {
        if (!g_vm) return;
        int rc = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (rc == JNI_EDETACHED) {
            if (g_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
            else env = nullptr;
        } else if (rc != JNI_OK) {
            env = nullptr;
        }
    }
    ~ScopedEnv() {
        if (attached && g_vm) g_vm->DetachCurrentThread();
    }
};

void clear_exception(JNIEnv* env) {
    if (env->ExceptionCheck()) { env->ExceptionClear(); }
}

// The shim class is the global ref cached from NativeBridge.s(); null until bootstrap runs
// (up-calls then degrade to empty/"unknown" — fail-open).
jclass find_shim(JNIEnv*) { return g_shim_cls; }

}  // namespace

void framework_shim_set_vm(JavaVM* vm) { g_vm = vm; }

JavaVM* framework_shim_get_vm() { return g_vm; }

// All framework values are fetched through the shim's single obfuscated entry
// point `q(int op, Object arg): Object` (so the shim has no descriptive method
// names for R8 to leave behind). These op codes are the fixed contract with
// FrameworkShim.q: 1 package, 2 uid, 3 sourceDir, 4 installer, 5 abi,
// 6 fingerprintAsset, 7 attestChain.
constexpr const char* kQ = "q";
constexpr const char* kQSig = "(ILjava/lang/Object;)Ljava/lang/Object;";

// Call q(op, arg) and return the raw local-ref result (or null). Caller holds the
// ScopedEnv [e] so the local ref stays valid until it processes/deletes it.
jobject fw_call(ScopedEnv& e, int op, jobject arg) {
    if (!e.env) return nullptr;
    jclass c = find_shim(e.env);
    if (!c) return nullptr;
    jmethodID m = e.env->GetStaticMethodID(c, kQ, kQSig);
    if (!m) { clear_exception(e.env); return nullptr; }
    jobject r = e.env->CallStaticObjectMethod(c, m, (jint)op, arg);
    if (e.env->ExceptionCheck()) { clear_exception(e.env); return nullptr; }
    return r;
}

std::string fw_call_string(int op) {
    ScopedEnv e;
    jobject r = fw_call(e, op, nullptr);
    if (!r) return "";
    // B1: string marshalling through the JNI_OnLoad vtable snapshot (the
    // table is process-wide, so the fns captured on the OnLoad env are valid
    // for this attached thread's env too — same reasoning as fw_call_int). A
    // late GetStringUTFChars hook cannot rewrite what the shim hands back.
    const jni_cache::Cache& jc = jni_cache::static_cache();
    auto chars = jni_cache::get<jni_cache::Slot::GetStringUTFChars,
                                jni_cache::getstringutfchars_fn>(jc);
    auto release = jni_cache::get<jni_cache::Slot::ReleaseStringUTFChars,
                                  jni_cache::releasestringutfchars_fn>(jc);
    const char* p = chars ? chars(e.env, (jstring)r, nullptr)
                          : e.env->GetStringUTFChars((jstring)r, nullptr);
    std::string s = p ? p : "";
    if (p) {
        if (release) release(e.env, (jstring)r, p);
        else e.env->ReleaseStringUTFChars((jstring)r, p);
    }
    e.env->DeleteLocalRef(r);
    return s;
}

int fw_call_int(int op) {
    ScopedEnv e;
    jobject r = fw_call(e, op, nullptr);  // boxed Integer
    if (!r) return -1;
    jclass icls = e.env->GetObjectClass(r);
    // B1: GetMethodID through the JNI_OnLoad vtable snapshot (the table is
    // process-wide, so the fn captured on the OnLoad env is valid for this
    // attached thread's env too — we pass e.env explicitly).
    jmethodID iv = icls
            ? jni_cache::get<jni_cache::Slot::GetMethodID, jni_cache::getmethodid_fn>(
                      jni_cache::static_cache())(e.env, icls, "intValue", "()I")
            : nullptr;
    int v = iv ? (int)e.env->CallIntMethod(r, iv) : -1;
    if (icls) e.env->DeleteLocalRef(icls);
    e.env->DeleteLocalRef(r);
    return v;
}

std::vector<std::vector<uint8_t>> fw_attest_chain(const uint8_t* nonce, size_t nonce_len) {
    std::vector<std::vector<uint8_t>> out;
    ScopedEnv e;
    if (!e.env) return out;
    jbyteArray jnonce = e.env->NewByteArray((jsize)nonce_len);
    if (!jnonce) return out;
    e.env->SetByteArrayRegion(jnonce, 0, (jsize)nonce_len,
                              reinterpret_cast<const jbyte*>(nonce));
    jobjectArray chain = (jobjectArray)fw_call(e, 7, jnonce);  // 7 = attestChain
    e.env->DeleteLocalRef(jnonce);
    if (!chain) return out;
    jsize n = e.env->GetArrayLength(chain);
    for (jsize i = 0; i < n; ++i) {
        jbyteArray der = (jbyteArray)e.env->GetObjectArrayElement(chain, i);
        if (!der) continue;
        jsize dl = e.env->GetArrayLength(der);
        std::vector<uint8_t> v((size_t)(dl > 0 ? dl : 0));
        if (dl > 0) e.env->GetByteArrayRegion(der, 0, dl, reinterpret_cast<jbyte*>(v.data()));
        out.push_back(std::move(v));
        e.env->DeleteLocalRef(der);
    }
    e.env->DeleteLocalRef(chain);
    return out;
}

// Attest-once session key (q op 14): returns [ SPKI-DER, leafCertDER, ...chainDER ].
std::vector<std::vector<uint8_t>> fw_session_keygen(const uint8_t* nonce, size_t nonce_len) {
    std::vector<std::vector<uint8_t>> out;
    ScopedEnv e;
    if (!e.env) return out;
    jbyteArray jnonce = e.env->NewByteArray((jsize)nonce_len);
    if (!jnonce) return out;
    e.env->SetByteArrayRegion(jnonce, 0, (jsize)nonce_len, reinterpret_cast<const jbyte*>(nonce));
    jobjectArray arr = (jobjectArray)fw_call(e, 14, jnonce);  // 14 = session keygen
    e.env->DeleteLocalRef(jnonce);
    if (!arr) return out;
    jsize n = e.env->GetArrayLength(arr);
    for (jsize i = 0; i < n; ++i) {
        jbyteArray der = (jbyteArray)e.env->GetObjectArrayElement(arr, i);
        if (!der) continue;
        jsize dl = e.env->GetArrayLength(der);
        std::vector<uint8_t> v((size_t)(dl > 0 ? dl : 0));
        if (dl > 0) e.env->GetByteArrayRegion(der, 0, dl, reinterpret_cast<jbyte*>(v.data()));
        out.push_back(std::move(v));
        e.env->DeleteLocalRef(der);
    }
    e.env->DeleteLocalRef(arr);
    return out;
}

// Attest-once session sign (q op 15): ECDSA-sign msg with the session key -> signature bytes.
bool fw_session_sign(const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out) {
    ScopedEnv e;
    if (!e.env) return false;
    jbyteArray jmsg = e.env->NewByteArray((jsize)msg_len);
    if (!jmsg) return false;
    e.env->SetByteArrayRegion(jmsg, 0, (jsize)msg_len, reinterpret_cast<const jbyte*>(msg));
    jbyteArray sig = (jbyteArray)fw_call(e, 15, jmsg);  // 15 = session sign
    e.env->DeleteLocalRef(jmsg);
    if (!sig) return false;
    jsize l = e.env->GetArrayLength(sig);
    out.resize((size_t)(l > 0 ? l : 0));
    if (l > 0) e.env->GetByteArrayRegion(sig, 0, l, reinterpret_cast<jbyte*>(out.data()));
    e.env->DeleteLocalRef(sig);
    return l > 0;
}

// The SOFTWARE rung of the signing ladder (q ops 19/20), used only when the
// attested session key is unavailable. It carries NO claim about the device — no
// attestation, no hardware root of trust — and the backend treats what it signs as
// unauthenticated. Its value is continuity across the scans of one process.
std::vector<uint8_t> fw_fallback_key_spki() {
    ScopedEnv e;
    std::vector<uint8_t> out;
    if (!e.env) return out;
    jbyteArray spki = (jbyteArray)fw_call(e, 19, nullptr);   // 19 = fallback key SPKI
    if (!spki) return out;
    jsize l = e.env->GetArrayLength(spki);
    out.resize((size_t)(l > 0 ? l : 0));
    if (l > 0) e.env->GetByteArrayRegion(spki, 0, l, reinterpret_cast<jbyte*>(out.data()));
    e.env->DeleteLocalRef(spki);
    return out;
}

bool fw_fallback_sign(const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out) {
    ScopedEnv e;
    if (!e.env) return false;
    jbyteArray jmsg = e.env->NewByteArray((jsize)msg_len);
    if (!jmsg) return false;
    e.env->SetByteArrayRegion(jmsg, 0, (jsize)msg_len, reinterpret_cast<const jbyte*>(msg));
    jbyteArray sig = (jbyteArray)fw_call(e, 20, jmsg);       // 20 = fallback sign
    e.env->DeleteLocalRef(jmsg);
    if (!sig) return false;
    jsize l = e.env->GetArrayLength(sig);
    out.resize((size_t)(l > 0 ? l : 0));
    if (l > 0) e.env->GetByteArrayRegion(sig, 0, l, reinterpret_cast<jbyte*>(out.data()));
    e.env->DeleteLocalRef(sig);
    return l > 0;
}

// Why the last attested keygen failed, e.g. "strongbox_unavailable:-68". Carried in
// a degraded token so the backend can separate a device/OEM fault from an injection.
// Self-reported and unsigned there, so it classifies but never exonerates.
std::string fw_last_keygen_error() { return fw_call_string(21); }

// Cross-level attestation (q op 8): the shim returns Object[2] = { byte[][],
// byte[][] } = { strongBoxChain, teeChain }. Unpack both into native vectors.
std::vector<std::vector<std::vector<uint8_t>>>
fw_attest_chains_xlevel(const uint8_t* nonce, size_t nonce_len) {
    std::vector<std::vector<std::vector<uint8_t>>> out;
    ScopedEnv e;
    if (!e.env) return out;
    jbyteArray jnonce = e.env->NewByteArray((jsize)nonce_len);
    if (!jnonce) return out;
    e.env->SetByteArrayRegion(jnonce, 0, (jsize)nonce_len,
                              reinterpret_cast<const jbyte*>(nonce));
    jobjectArray pair = (jobjectArray)fw_call(e, 8, jnonce);  // 8 = cross-level attest
    e.env->DeleteLocalRef(jnonce);
    if (!pair) return out;
    jsize np = e.env->GetArrayLength(pair);
    for (jsize i = 0; i < np; ++i) {
        std::vector<std::vector<uint8_t>> chain;
        jobjectArray jchain = (jobjectArray)e.env->GetObjectArrayElement(pair, i);
        if (jchain) {
            jsize n = e.env->GetArrayLength(jchain);
            for (jsize k = 0; k < n; ++k) {
                jbyteArray der = (jbyteArray)e.env->GetObjectArrayElement(jchain, k);
                if (!der) continue;
                jsize dl = e.env->GetArrayLength(der);
                std::vector<uint8_t> v((size_t)(dl > 0 ? dl : 0));
                if (dl > 0) e.env->GetByteArrayRegion(der, 0, dl, reinterpret_cast<jbyte*>(v.data()));
                chain.push_back(std::move(v));
                e.env->DeleteLocalRef(der);
            }
            e.env->DeleteLocalRef(jchain);
        }
        out.push_back(std::move(chain));
    }
    e.env->DeleteLocalRef(pair);
    return out;
}

// APK asset entry paths inside the zip (must match FrameworkShim's constants).
constexpr const char* kFingerprintAssetPath =
    "assets/tech.thessemaj.deviceintelligence/fingerprint.bin";
constexpr const char* kCrlAssetPath =
    "assets/tech.thessemaj.deviceintelligence/crl.bin";
constexpr const char* kLicenceAssetPath =
    "assets/tech.thessemaj.deviceintelligence/server.key";

// Read an APK asset natively: resolve base.apk from /proc/self/maps, mmap it, and
// pull the decompressed entry. No JVM up-call, so an LSPosed hook on FrameworkShim.q
// cannot forge/starve the asset. Empty on any failure (e.g. an extractNativeLibs
// install where base.apk is not mmapped) -> caller falls back to the up-call.
static std::vector<uint8_t> native_apk_asset(const char* entry_name) {
    std::vector<uint8_t> out;
    char apk[1024] = {0};
    // OUR base.apk, matched by package component — not merely the first one mapped.
    // An Xposed module's APK is mapped into the target process and can sort ahead of
    // ours; reading assets from that one finds nothing, and for the licence blob
    // (native-only, no JVM fallback) that meant the SDK emitted NO TOKEN AT ALL.
    // Measured on-device with an enabled module. Falling back to first-match keeps
    // odd installs working, but the package match is what makes it correct.
    const std::string self = fw_package_name();
    if (cloner::read_own_apk_path_from_maps(self.c_str(), apk, sizeof(apk)) <= 0 || apk[0] == '\0') {
        if (cloner::read_apk_path_from_maps(apk, sizeof(apk)) <= 0 || apk[0] == '\0') return out;
    }
    ApkMap map;
    if (!map.open(apk)) return out;
    zip::CentralDirInfo cdi{};
    if (!zip::find_central_directory(map, &cdi)) return out;
    (void)zip::read_entry_raw(map, cdi, entry_name, &out);   // out stays empty on miss
    return out;
}

// Read the raw bytes of asset [op]/[entry_name] via the JVM up-call (fallback only).
static std::vector<uint8_t> jvm_asset(int op) {
    std::vector<uint8_t> out;
    ScopedEnv e;
    jbyteArray arr = (jbyteArray)fw_call(e, op, nullptr);
    if (!arr) return out;
    jsize n = e.env->GetArrayLength(arr);
    if (n > 0) {
        out.resize((size_t)n);
        e.env->GetByteArrayRegion(arr, 0, n, reinterpret_cast<jbyte*>(out.data()));
    }
    e.env->DeleteLocalRef(arr);
    return out;
}

// The encrypted fingerprint baseline bytes. Native-first (reads base.apk directly);
// falls back to the JVM up-call (q op 6) only if native path resolution failed.
std::vector<uint8_t> fw_fingerprint_asset() {
    std::vector<uint8_t> v = native_apk_asset(kFingerprintAssetPath);
    if (!v.empty()) return v;
    return jvm_asset(6);
}

// The encrypted CRL asset bytes. Native-first; JVM up-call (q op 9) is the fallback.
std::vector<uint8_t> fw_crl_asset() {
    std::vector<uint8_t> v = native_apk_asset(kCrlAssetPath);
    if (!v.empty()) return v;
    return jvm_asset(9);
}

// The pinned server public key (server.key). Native-ONLY: v2 tokens must not
// introduce a new ART-hookable JVM asset up-call, so there is no jvm_asset fallback
// (spec §5). Empty on any failure -> the caller fails closed.
std::vector<uint8_t> fw_licence_asset() {
    return native_apk_asset(kLicenceAssetPath);
}

// ---- Native-resolved framework values (no JVM up-call) ---------------------
// These carry no ART-hookable surface: an LSPosed hook on FrameworkShim.q can no
// longer forge the package or abi the detectors read. They also need no Context and
// can answer before bootstrap. Correctness is unambiguous — the native source is
// authoritative (the compiled ABI is exactly the one libdicore loaded for;
// cmdline[0] is the process/package name).
//
// A third, fw_uid() (getuid == Process.myUid), was moved here alongside them and
// then never called by any detector; it was removed rather than left as a surface
// nothing consumes.

std::string fw_primary_abi() {
    // The ABI libdicore was built for — more reliable than Build.SUPPORTED_ABIS[0]
    // (which is the device's preferred ABI, not necessarily the one we loaded).
#if defined(__aarch64__)
    return "arm64-v8a";
#elif defined(__arm__)
    return "armeabi-v7a";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#else
    return "";
#endif
}

std::string fw_package_name() {
    // /proc/self/cmdline's first NUL-terminated token is the process name, which
    // is the package for the app process (barring an android:process override,
    // which the detection package does not use).
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "";
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);   // stops at the first embedded NUL
}

// sourceDir = this app's base.apk, resolved from /proc/self/maps. Falls back to the
// JVM up-call (q op 3) only if base.apk isn't mmapped (legacy extractNativeLibs).
std::string fw_source_dir() {
    char apk[1024] = {0};
    // OURS, by package component. Taking whichever base.apk is mapped FIRST was a
    // false-positive cannon, not merely a blind spot: an Xposed/Zygisk module's APK
    // sorts ahead of the app's own on a rooted device, and the apk self-integrity
    // detector then diffed a FOREIGN apk against our baked baseline — measured
    // on-device as 707 apk_entry_added, 40 removed, 4 modified and a signer
    // mismatch, all of them blocking, on a perfectly legitimate app.
    const std::string self = fw_package_name();
    if (cloner::read_own_apk_path_from_maps(self.c_str(), apk, sizeof(apk)) > 0 && apk[0] != '\0')
        return std::string(apk);
    // Only then fall back: first-match keeps odd installs working, and the JVM
    // up-call is the last resort when base.apk is not mmapped at all.
    if (cloner::read_apk_path_from_maps(apk, sizeof(apk)) > 0 && apk[0] != '\0')
        return std::string(apk);
    return fw_call_string(3);
}

std::string fw_installer_package() { return fw_call_string(4); }

// "1"/"0"/"" — whether this device declares FEATURE_STRONGBOX_KEYSTORE. Acquisition
// only; the backend decides what it means (see FrameworkShim.a18).
std::string fw_strongbox_feature() { return fw_call_string(16); }
std::string fw_signing_digest()    { return fw_call_string(17); }
std::string fw_fingerprint_raw()   { return fw_call_string(18); }

// Enumerate this app's split APKs from /proc/self/maps natively: every mapped
// `/data/**/*.apk` that carries our package name and is NOT base.apk. Deduped.
static std::vector<std::string> native_split_paths() {
    std::vector<std::string> out;
    const std::string pkg = fw_package_name();
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return out;
    std::string maps;
    char buf[8192]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) maps.append(buf, (size_t)n);
    close(fd);

    size_t pos = 0;
    while (pos < maps.size()) {
        size_t nl = maps.find('\n', pos);
        std::string line = maps.substr(pos, nl == std::string::npos ? maps.size() - pos : nl - pos);
        pos = (nl == std::string::npos) ? maps.size() : nl + 1;
        size_t sp = line.find_last_of(' ');
        if (sp == std::string::npos) continue;
        std::string path = line.substr(sp + 1);
        if (path.compare(0, 6, "/data/") != 0) continue;                       // app apks only
        if (path.size() < 4 || path.compare(path.size() - 4, 4, ".apk") != 0) continue;
        if (path.size() >= 9 && path.compare(path.size() - 9, 9, "/base.apk") == 0) continue;
        if (!pkg.empty() && path.find(pkg) == std::string::npos) continue;     // must be ours
        if (std::find(out.begin(), out.end(), path) == out.end()) out.push_back(path);
    }
    return out;
}

std::vector<std::string> split_source_dirs() {
    // Native-first: enumerate mapped split APKs from /proc/self/maps.
    std::vector<std::string> native = native_split_paths();
    if (!native.empty()) return native;
    // Fallback (q op 10, '\n'-joined) — covers splits present but not yet mmapped
    // (App Bundle lazy load) and the extractNativeLibs case. Empty is a valid "no
    // splits" answer for a single-APK install.
    std::string joined = fw_call_string(10);
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= joined.size()) {
        size_t nl = joined.find('\n', start);
        std::string part = (nl == std::string::npos)
                               ? joined.substr(start)
                               : joined.substr(start, nl - start);
        if (!part.empty()) out.push_back(std::move(part));
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return out;
}

// op 13: dex-provenance enumeration. Returns String[] of
// "<loaderClass>\x1f<dexPathOrEmpty>", one per dex element in a reachable loader.
std::vector<std::string> fw_dex_entries() {
    std::vector<std::string> out;
    ScopedEnv e;
    if (!e.env) return out;
    jobjectArray arr = (jobjectArray)fw_call(e, 13, nullptr);  // 13 = dex provenance
    if (!arr) return out;
    jsize n = e.env->GetArrayLength(arr);
    for (jsize i = 0; i < n; ++i) {
        jstring s = (jstring)e.env->GetObjectArrayElement(arr, i);
        if (!s) continue;
        // B1: snapshot-cache marshalling, same as fw_call_string.
        const jni_cache::Cache& jc = jni_cache::static_cache();
        auto chars = jni_cache::get<jni_cache::Slot::GetStringUTFChars,
                                    jni_cache::getstringutfchars_fn>(jc);
        auto release = jni_cache::get<jni_cache::Slot::ReleaseStringUTFChars,
                                      jni_cache::releasestringutfchars_fn>(jc);
        const char* p = chars ? chars(e.env, s, nullptr)
                              : e.env->GetStringUTFChars(s, nullptr);
        if (p) {
            out.emplace_back(p);
            if (release) release(e.env, s, p);
            else e.env->ReleaseStringUTFChars(s, p);
        }
        e.env->DeleteLocalRef(s);
    }
    e.env->DeleteLocalRef(arr);
    return out;
}

// op 11: this device's identity as "brand\ndevice\nproduct\nmanufacturer\nmodel".
// Parsed positionally; ok only if all five non-empty fields were present.
DeviceIdentity fw_device_identity() {
    DeviceIdentity id;
    std::string joined = fw_call_string(11);
    if (joined.empty()) return id;
    std::string* fields[5] = {&id.brand, &id.device, &id.product,
                              &id.manufacturer, &id.model};
    size_t start = 0;
    int i = 0;
    while (i < 5) {
        size_t nl = joined.find('\n', start);
        *fields[i] = (nl == std::string::npos) ? joined.substr(start)
                                               : joined.substr(start, nl - start);
        ++i;
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    id.ok = (i == 5) && !id.brand.empty() && !id.device.empty()
         && !id.product.empty() && !id.manufacturer.empty() && !id.model.empty();
    return id;
}

// NativeBridge.s(Class) — bootstrap hands us the framework-shim class; hold a global ref so
// the up-calls (possibly on the orchestrator's attached thread) can reach it
// without a fixed-name FindClass. Idempotent; replaces any prior ref.
DI_OBF_MAX
void JNICALL anchors::nat_register_shim(JNIEnv* env, jclass, jclass shim) {
    if (shim == nullptr) return;
    if (g_shim_cls != nullptr) env->DeleteGlobalRef(g_shim_cls);
    g_shim_cls = (jclass)env->NewGlobalRef(shim);
}

}  // namespace dicore
