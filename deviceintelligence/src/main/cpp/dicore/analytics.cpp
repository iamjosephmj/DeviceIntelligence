// analytics.cpp — fire-and-forget event delivery to the SDK author's
// analytics endpoint.
//
// Analytics is ON by default. The opt-out path is the Gradle plugin DSL:
//   deviceintelligence { disableAnalytics.set(true) }
// which injects:
//   <meta-data android:name="io.ssemaj.di.analytics" android:value="disabled"/>
// analytics::init() reads that flag at startup and skips all further work.
//
// Network I/O runs on a single detached background pthread via
// java.net.HttpURLConnection JNI — no native TLS stack needed.
// All calls are fire-and-forget; HTTP errors are silently discarded.
//
// Wire format: clean nested JSON POST to kEndpointUrl with a stable
// envelope (event/timestamp/sdk/consumer/device/params). Backend can store
// raw, decode, aggregate, or relay to whatever analytics platform.
//
// Data collected: device hardware signals only (ABI, API level, manufacturer,
// model, SoC, CPU vendor from emulator probe, ART/native integrity result
// codes, mount filesystem types without paths, library basenames without
// directory paths). No package names, cert hashes, memory addresses, or
// user-identifiable data are ever queued.

#include "analytics.h"
#include "log.h"
#include "sha256.h"

#include <jni.h>
#include <pthread.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace dicore::analytics {

namespace {

// ── Endpoint configuration ───────────────────────────────────────────────────
// kEndpointUrl is the HTTPS analytics endpoint events are POSTed to.
//
// QUICK VERIFICATION (no backend required): use https://webhook.site to get a
// throwaway URL that displays every incoming POST in your browser in real-
// time. Visit webhook.site, copy the unique URL it generates for you, paste
// it here, rebuild, run the app, and watch events appear instantly.
//
// PRODUCTION: replace with your own endpoint that accepts POST with
// Content-Type: application/json. The backend is responsible for parsing,
// storing, and (optionally) forwarding to whatever analytics platform.
static const char kEndpointUrl[] =
    "https://us-central1-deviceintelligence-ca062.cloudfunctions.net/ingest";

// Optional shared secret — if non-empty, sent in the X-DI-Auth header so the
// backend can reject unauthenticated traffic. Empty string disables the
// header entirely.
static const char kSharedSecret[] = "";

// When true, every HTTP response is logged at INFO/WARN level under the
// "dicore" tag. Flip to false to silence delivery logging in release builds.
static constexpr bool kLogHttpStatus = true;

// ── manifest opt-out key ────────────────────────────────────────────────────
static const char kOptOutKey[]   = "io.ssemaj.di.analytics";
static const char kOptOutValue[] = "disabled";

// ── ring buffer ─────────────────────────────────────────────────────────────
constexpr size_t kRingMax = 64;

// Event payloads are heap-backed because the largest payload — the full
// telemetry_report JSON dumped at collect() time — can run to tens of KB
// (rich device context + attestation chain hashes + per-detector findings).
// Fixed char arrays would force a hard truncation cap; std::string lets
// each event size itself.
struct Event {
    std::string name;
    std::string params;
};

// ── globals ──────────────────────────────────────────────────────────────────
static JavaVM*           g_jvm       = nullptr;
static std::atomic<bool> g_enabled{false};
static char              g_client_id[65]    = {};
static char              g_sdk_ver[32]      = {};
// Consumer-app identity. Captured once at init from ApplicationInfo +
// PackageInfo. Surfaces on every event so the backend can group events by
// host app ("events from io.bank.app vs events from io.shopping.app").
static char              g_consumer_pkg[128] = {};
static char              g_consumer_ver[32]  = {};
// Session identifier — seconds since epoch at process start. Stamped on
// every event so the backend can group events emitted within the same
// process run without needing per-event correlation logic.
static long              g_session_id = 0;

static pthread_mutex_t   g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    g_cond = PTHREAD_COND_INITIALIZER;
static std::vector<Event> g_queue;

// ── helpers ──────────────────────────────────────────────────────────────────

static void bytes_to_hex(const uint8_t* src, size_t len, char* dst) {
    static const char kH[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        dst[i * 2]     = kH[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = kH[ src[i]       & 0xF];
    }
    dst[len * 2] = '\0';
}

// device_id is hashed from (device_fingerprint || consumer_package) so:
//   - Same device + same consumer → stable ID across runs (correct cohorting)
//   - Same device + different consumers → distinct IDs (correct partitioning)
//   - Different devices + same consumer → distinct IDs (one user per device)
// This is what every commercial SDK does (Sentry/Crashlytics/Mixpanel) —
// the SDK author runs one analytics endpoint, with consumer-scoped IDs.
static void derive_client_id() {
    char fp[256] = {};
    __system_property_get("ro.build.fingerprint", fp);
    if (!fp[0]) {
        snprintf(g_client_id, sizeof(g_client_id), "unknown");
        return;
    }
    char composite[512];
    snprintf(composite, sizeof(composite), "%s|%s", fp,
             g_consumer_pkg[0] ? g_consumer_pkg : "anon");
    uint8_t digest[sha::kDigestLen];
    if (!sha::sha256(composite, strlen(composite), digest)) {
        snprintf(g_client_id, sizeof(g_client_id), "hash_err");
        return;
    }
    bytes_to_hex(digest, sha::kDigestLen, g_client_id);
}

// ── consumer-app identity ────────────────────────────────────────────────────

// Reads the host (consumer) app's package name and version, storing into
// g_consumer_pkg / g_consumer_ver. Both are captured fresh on every init so
// SDKs that span multiple processes report each process's identity correctly.
// On any failure the globals are left empty — the analytics layer still works
// with anonymous "anon" identity.
static void read_consumer_identity(JNIEnv* env) {
    g_consumer_pkg[0] = '\0';
    g_consumer_ver[0] = '\0';

    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (!atCls) { env->ExceptionClear(); return; }
    jmethodID midCA = env->GetStaticMethodID(atCls, "currentApplication",
                                              "()Landroid/app/Application;");
    if (!midCA || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(atCls); return;
    }
    jobject app = env->CallStaticObjectMethod(atCls, midCA);
    env->DeleteLocalRef(atCls);
    if (env->ExceptionCheck() || !app) { env->ExceptionClear(); return; }

    // getPackageName()
    jclass appCls = env->GetObjectClass(app);
    jmethodID midPN = env->GetMethodID(appCls, "getPackageName",
                                        "()Ljava/lang/String;");
    jmethodID midPM = env->GetMethodID(appCls, "getPackageManager",
                                        "()Landroid/content/pm/PackageManager;");
    env->DeleteLocalRef(appCls);
    if (!midPN || !midPM || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(app); return;
    }
    jstring jPkg = static_cast<jstring>(env->CallObjectMethod(app, midPN));
    if (env->ExceptionCheck() || !jPkg) {
        env->ExceptionClear(); env->DeleteLocalRef(app);
        if (jPkg) env->DeleteLocalRef(jPkg);
        return;
    }
    const char* pkg = env->GetStringUTFChars(jPkg, nullptr);
    if (pkg) {
        snprintf(g_consumer_pkg, sizeof(g_consumer_pkg), "%s", pkg);
        env->ReleaseStringUTFChars(jPkg, pkg);
    }

    // getPackageManager().getPackageInfo(pkg, 0).versionName
    jobject pm = env->CallObjectMethod(app, midPM);
    env->DeleteLocalRef(app);
    if (env->ExceptionCheck() || !pm) {
        env->ExceptionClear(); env->DeleteLocalRef(jPkg);
        return;
    }
    jclass pmCls = env->GetObjectClass(pm);
    jmethodID midPI = env->GetMethodID(pmCls, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pmCls);
    if (!midPI || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(jPkg); env->DeleteLocalRef(pm);
        return;
    }
    jobject pi = env->CallObjectMethod(pm, midPI, jPkg, (jint)0);
    env->DeleteLocalRef(pm); env->DeleteLocalRef(jPkg);
    if (env->ExceptionCheck() || !pi) { env->ExceptionClear(); return; }

    jclass piCls = env->GetObjectClass(pi);
    jfieldID fidVN = env->GetFieldID(piCls, "versionName", "Ljava/lang/String;");
    env->DeleteLocalRef(piCls);
    if (!fidVN || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(pi); return;
    }
    jstring jVer = static_cast<jstring>(env->GetObjectField(pi, fidVN));
    env->DeleteLocalRef(pi);
    if (!jVer) return;
    const char* ver = env->GetStringUTFChars(jVer, nullptr);
    if (ver) {
        snprintf(g_consumer_ver, sizeof(g_consumer_ver), "%s", ver);
        env->ReleaseStringUTFChars(jVer, ver);
    }
    env->DeleteLocalRef(jVer);
}

// ── opt-out flag: read manifest <meta-data> ──────────────────────────────────

static bool read_opt_out(JNIEnv* env) {
    // ActivityThread.currentApplication() → Application (Context)
    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (!atCls) { env->ExceptionClear(); return false; }
    jmethodID midCA = env->GetStaticMethodID(atCls, "currentApplication",
                                              "()Landroid/app/Application;");
    if (!midCA || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(atCls); return false;
    }
    jobject app = env->CallStaticObjectMethod(atCls, midCA);
    env->DeleteLocalRef(atCls);
    if (env->ExceptionCheck() || !app) { env->ExceptionClear(); return false; }

    jclass appCls = env->GetObjectClass(app);
    jmethodID midPN = env->GetMethodID(appCls, "getPackageName",
                                        "()Ljava/lang/String;");
    jmethodID midPM = env->GetMethodID(appCls, "getPackageManager",
                                        "()Landroid/content/pm/PackageManager;");
    env->DeleteLocalRef(appCls);
    if (!midPN || !midPM || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(app); return false;
    }
    jstring jPkg = static_cast<jstring>(env->CallObjectMethod(app, midPN));
    jobject  pm  = env->CallObjectMethod(app, midPM);
    env->DeleteLocalRef(app);
    if (env->ExceptionCheck() || !jPkg || !pm) {
        env->ExceptionClear();
        if (jPkg) env->DeleteLocalRef(jPkg);
        if (pm)   env->DeleteLocalRef(pm);
        return false;
    }

    // PackageManager.getApplicationInfo(pkgName, GET_META_DATA=128)
    jclass pmCls = env->GetObjectClass(pm);
    jmethodID midAI = env->GetMethodID(pmCls, "getApplicationInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
    env->DeleteLocalRef(pmCls);
    if (!midAI || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(jPkg); env->DeleteLocalRef(pm);
        return false;
    }
    jobject ai = env->CallObjectMethod(pm, midAI, jPkg, (jint)128);
    env->DeleteLocalRef(pm); env->DeleteLocalRef(jPkg);
    if (env->ExceptionCheck() || !ai) { env->ExceptionClear(); return false; }

    // ApplicationInfo.metaData (Bundle)
    jclass aiCls = env->GetObjectClass(ai);
    jfieldID fidMeta = env->GetFieldID(aiCls, "metaData", "Landroid/os/Bundle;");
    env->DeleteLocalRef(aiCls);
    if (!fidMeta || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(ai); return false;
    }
    jobject bundle = env->GetObjectField(ai, fidMeta);
    env->DeleteLocalRef(ai);
    if (!bundle) return false; // no meta-data → not opted out

    // Bundle.getString(key)
    jclass bndCls = env->GetObjectClass(bundle);
    jmethodID midGS = env->GetMethodID(bndCls, "getString",
                                        "(Ljava/lang/String;)Ljava/lang/String;");
    env->DeleteLocalRef(bndCls);
    if (!midGS || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(bundle); return false;
    }
    jstring jKey = env->NewStringUTF(kOptOutKey);
    jstring jVal = static_cast<jstring>(env->CallObjectMethod(bundle, midGS, jKey));
    env->DeleteLocalRef(bundle); env->DeleteLocalRef(jKey);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!jVal) return false; // key absent → not opted out

    const char* val = env->GetStringUTFChars(jVal, nullptr);
    bool disabled = val && strcmp(val, kOptOutValue) == 0;
    if (val) env->ReleaseStringUTFChars(jVal, val);
    env->DeleteLocalRef(jVal);
    return disabled;
}

// ── SDK version from BuildConfig ─────────────────────────────────────────────

static void read_sdk_version(JNIEnv* env) {
    jclass bcCls = env->FindClass("io/ssemaj/deviceintelligence/BuildConfig");
    if (!bcCls || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jfieldID fid = env->GetStaticFieldID(bcCls, "LIBRARY_VERSION",
                                          "Ljava/lang/String;");
    if (!fid || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(bcCls); return;
    }
    jstring jVer = static_cast<jstring>(env->GetStaticObjectField(bcCls, fid));
    env->DeleteLocalRef(bcCls);
    if (!jVer || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    const char* ver = env->GetStringUTFChars(jVer, nullptr);
    if (ver) snprintf(g_sdk_ver, sizeof(g_sdk_ver), "%s", ver);
    if (ver) env->ReleaseStringUTFChars(jVer, ver);
    env->DeleteLocalRef(jVer);
}

// ── HTTP POST to the configured analytics endpoint ───────────────────────────

// Posts a JSON body to kEndpointUrl. Fire-and-forget; HTTP errors are logged
// at WARN when kLogHttpStatus is true and otherwise ignored.
static void http_post(JNIEnv* env, const char* body_json) {
    const char* url = kEndpointUrl;

    // new URL(urlStr)
    jclass urlCls = env->FindClass("java/net/URL");
    if (!urlCls || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jmethodID urlInit = env->GetMethodID(urlCls, "<init>",
                                          "(Ljava/lang/String;)V");
    if (!urlInit || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(urlCls); return;
    }
    jstring jUrl = env->NewStringUTF(url);
    jobject urlObj = env->NewObject(urlCls, urlInit, jUrl);
    env->DeleteLocalRef(urlCls); env->DeleteLocalRef(jUrl);
    if (env->ExceptionCheck() || !urlObj) { env->ExceptionClear(); return; }

    // url.openConnection() → HttpURLConnection
    jclass urlCls2 = env->GetObjectClass(urlObj);
    jmethodID midOC = env->GetMethodID(urlCls2, "openConnection",
                                        "()Ljava/net/URLConnection;");
    env->DeleteLocalRef(urlCls2);
    if (!midOC || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(urlObj); return;
    }
    jobject conn = env->CallObjectMethod(urlObj, midOC);
    env->DeleteLocalRef(urlObj);
    if (env->ExceptionCheck() || !conn) { env->ExceptionClear(); return; }

    // Resolve all methods upfront — bail if any are missing.
    jclass connCls = env->GetObjectClass(conn);
    auto getM = [&](const char* name, const char* sig) -> jmethodID {
        jmethodID m = env->GetMethodID(connCls, name, sig);
        if (env->ExceptionCheck()) env->ExceptionClear();
        return m;
    };
    jmethodID midSRM = getM("setRequestMethod",  "(Ljava/lang/String;)V");
    jmethodID midSDO = getM("setDoOutput",        "(Z)V");
    jmethodID midSCT = getM("setConnectTimeout",  "(I)V");
    jmethodID midSRT = getM("setReadTimeout",     "(I)V");
    jmethodID midSRP = getM("setRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V");
    jmethodID midGOS = getM("getOutputStream",    "()Ljava/io/OutputStream;");
    jmethodID midGRC = getM("getResponseCode",    "()I");
    jmethodID midDC  = getM("disconnect",         "()V");
    if (!midSRM || !midSDO || !midSCT || !midSRT ||
        !midSRP || !midGOS || !midGRC || !midDC) {
        env->DeleteLocalRef(conn); env->DeleteLocalRef(connCls); return;
    }

    jstring jPost = env->NewStringUTF("POST");
    env->CallVoidMethod(conn, midSRM, jPost); env->DeleteLocalRef(jPost);
    env->CallVoidMethod(conn, midSDO, JNI_TRUE);
    env->CallVoidMethod(conn, midSCT, (jint)5000);
    env->CallVoidMethod(conn, midSRT, (jint)5000);
    jstring jCTK = env->NewStringUTF("Content-Type");
    jstring jCTV = env->NewStringUTF("application/json; charset=utf-8");
    env->CallVoidMethod(conn, midSRP, jCTK, jCTV);
    env->DeleteLocalRef(jCTK); env->DeleteLocalRef(jCTV);
    // Optional X-DI-Auth header for backend authentication.
    if (kSharedSecret[0] != '\0') {
        jstring jAK = env->NewStringUTF("X-DI-Auth");
        jstring jAV = env->NewStringUTF(kSharedSecret);
        env->CallVoidMethod(conn, midSRP, jAK, jAV);
        env->DeleteLocalRef(jAK); env->DeleteLocalRef(jAV);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(conn); env->DeleteLocalRef(connCls); return;
    }

    // getOutputStream().write(body_bytes)
    jobject os = env->CallObjectMethod(conn, midGOS);
    if (env->ExceptionCheck() || !os) {
        env->ExceptionClear();
        env->DeleteLocalRef(conn); env->DeleteLocalRef(connCls); return;
    }
    jclass osCls = env->GetObjectClass(os);
    jmethodID midWrite = env->GetMethodID(osCls, "write", "([B)V");
    env->DeleteLocalRef(osCls);
    if (midWrite && !env->ExceptionCheck()) {
        const jsize blen = static_cast<jsize>(strlen(body_json));
        jbyteArray jBody = env->NewByteArray(blen);
        if (jBody) {
            env->SetByteArrayRegion(jBody, 0, blen,
                                    reinterpret_cast<const jbyte*>(body_json));
            env->CallVoidMethod(os, midWrite, jBody);
            env->DeleteLocalRef(jBody);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(os);

    // getResponseCode() actually fires the HTTP request. When kLogHttpStatus
    // is true the response code is logged so integrators can confirm events
    // are reaching the backend.
    jint code = env->CallIntMethod(conn, midGRC);
    if (kLogHttpStatus) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            RLOGW("analytics: HTTP request raised exception");
        } else if (code >= 200 && code < 300) {
            RLOGI("analytics: event delivered (HTTP %d)",
                  static_cast<int>(code));
        } else {
            RLOGW("analytics: event rejected (HTTP %d)",
                  static_cast<int>(code));
        }
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    env->CallVoidMethod(conn, midDC);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(conn);
    env->DeleteLocalRef(connCls);
}

// ── drain thread ─────────────────────────────────────────────────────────────

static void* drain_fn(void* /*arg*/) {
    JavaVM* vm = g_jvm;
    if (!vm) return nullptr;

    JNIEnv* env = nullptr;
    JavaVMAttachArgs args{};
    args.version = JNI_VERSION_1_6;
    args.name    = const_cast<char*>("di-analytics");
    args.group   = nullptr;
    if (vm->AttachCurrentThread(&env, &args) != JNI_OK || !env) {
        RLOGE("analytics: drain: AttachCurrentThread failed");
        return nullptr;
    }

    // Poll for consumer identity. JNI_OnLoad runs before Application is
    // constructed, so ActivityThread.currentApplication() returns null at
    // init time. By the time this thread reaches Java code (a few hundred
    // µs after init), the Application instance is usually up; on slow
    // devices it can take up to ~1s. Cap the wait at 5s (50 × 100ms) and
    // proceed with "anon" if the Application is still missing — better to
    // ship an unattributed event than block the drain forever.
    for (int i = 0; i < 50; ++i) {
        read_consumer_identity(env);
        if (g_consumer_pkg[0]) break;
        usleep(100 * 1000);  // 100ms
    }
    if (!g_consumer_pkg[0]) snprintf(g_consumer_pkg, sizeof(g_consumer_pkg), "anon");
    if (!g_consumer_ver[0]) snprintf(g_consumer_ver, sizeof(g_consumer_ver), "unknown");
    // Re-derive device_id now that we have the consumer package — the
    // composite hash partitions IDs per (device, consumer).
    derive_client_id();
    RLOGI("analytics: identity captured (consumer=%s v%s)",
          g_consumer_pkg, g_consumer_ver);

    // session_start fires once per process so the backend can mark the
    // beginning of every run independently of any specific probe firing.
    queue_event("session_start", "{}");

    for (;;) {
        std::vector<Event> batch;
        pthread_mutex_lock(&g_lock);
        while (g_queue.empty()) {
            pthread_cond_wait(&g_cond, &g_lock);
        }
        g_queue.swap(batch);
        pthread_mutex_unlock(&g_lock);

        for (const Event& e : batch) {
            // SDK-owned JSON envelope. Top-level keys are the stable wire
            // contract for the backend; `params` is the per-event payload
            // emitted by individual probes or the full telemetry_report
            // JSON. Built into a std::string so it can grow with the
            // payload — telemetry_report can be tens of KB.
            std::string body;
            body.reserve(512 + e.params.size());
            body.append("{\"event\":\"");
            body.append(e.name);
            body.append("\",\"timestamp\":");

            char numbuf[32];
            snprintf(numbuf, sizeof(numbuf), "%ld",
                     static_cast<long>(time(nullptr)));
            body.append(numbuf);
            body.append(",\"session_id\":");
            snprintf(numbuf, sizeof(numbuf), "%ld", g_session_id);
            body.append(numbuf);

            body.append(",\"device_id\":\"");
            // device_id is hashed hex; truncate to 32 chars to match the
            // canonical short form used elsewhere in the wire contract.
            body.append(g_client_id, std::min<size_t>(32, strlen(g_client_id)));
            body.append("\",\"sdk\":{\"version\":\"");
            body.append(g_sdk_ver);
            body.append("\"},\"consumer\":{\"package\":\"");
            body.append(g_consumer_pkg);
            body.append("\",\"version\":\"");
            body.append(g_consumer_ver);
            body.append("\"},\"params\":");
            body.append(e.params);
            body.append("}");

            http_post(env, body.c_str());
        }
    }

    vm->DetachCurrentThread();
    return nullptr;
}

} // namespace

// ── public API ───────────────────────────────────────────────────────────────

void init(JavaVM* vm, JNIEnv* env) {
    g_jvm = vm;

    if (read_opt_out(env)) {
        RLOGI("analytics: disabled via manifest meta-data");
        g_enabled.store(false);
        return;
    }

    // BuildConfig + ro.* properties are available immediately. Consumer
    // identity is NOT — JNI_OnLoad runs before Application is constructed,
    // so ActivityThread.currentApplication() returns null here. The drain
    // thread polls for it once the Application is up; device_id is then
    // re-derived. Until that happens, events queued from JNI_OnLoad sit
    // in the buffer waiting for identity (no HTTP traffic until ready).
    read_sdk_version(env);
    if (!g_sdk_ver[0]) snprintf(g_sdk_ver, sizeof(g_sdk_ver), "unknown");

    // Mint a session ID once per process (seconds since epoch). Every event
    // is stamped with this so the backend can group all events from one run.
    g_session_id = static_cast<long>(time(nullptr));

    RLOGI("analytics: starting (sdk=%s, session=%ld, awaiting consumer identity)",
          g_sdk_ver, g_session_id);

    g_enabled.store(true);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, drain_fn, nullptr) != 0) {
        RLOGE("analytics: failed to start drain thread");
        g_enabled.store(false);
    }
    pthread_attr_destroy(&attr);

    // No `sdk_init` event is queued from here — the full device + firmware
    // identity is already shipped as part of the `telemetry_report` event
    // when the consumer calls `DeviceIntelligence.collect()`. The drain
    // thread queues a `session_start` once the consumer Application is
    // available so we always have a process-loaded heartbeat even on
    // devices that never call collect().
}

void queue_event(const char* name, const char* params_json) {
    if (!g_enabled.load()) return;
    if (!name || !params_json) return;

    Event e;
    e.name   = name;
    e.params = params_json;

    pthread_mutex_lock(&g_lock);
    if (g_queue.size() < kRingMax) {
        g_queue.push_back(std::move(e));
        pthread_cond_signal(&g_cond);
    }
    pthread_mutex_unlock(&g_lock);
}

} // namespace dicore::analytics
