#include "apkmap.h"
#include "hex.h"
#include "log.h"
#include "sha256.h"
#include "sigblock_parser.h"
#include "zip_parser.h"

#include <jni.h>
#include <vector>

namespace dicore {

namespace {

jstring make_jstring(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
}

jobjectArray strings_to_jarray(JNIEnv* env, const std::vector<std::string>& v) {
    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray arr = env->NewObjectArray((jsize)v.size(), strCls, nullptr);
    if (!arr) return nullptr;
    for (size_t i = 0; i < v.size(); ++i) {
        jstring js = make_jstring(env, v[i]);
        if (!js) return nullptr;
        env->SetObjectArrayElement(arr, (jsize)i, js);
        env->DeleteLocalRef(js);
    }
    return arr;
}

} // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_nativeReady(JNIEnv*, jclass) {
    return sha::ensure_initialized() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkEntries(JNIEnv* env, jclass,
                                                     jstring jpath) {
    if (!jpath) return nullptr;
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;

    ApkMap apk;
    bool ok = apk.open(path);
    env->ReleaseStringUTFChars(jpath, path);
    if (!ok) {
        RLOGE("apkEntries: open failed: %s (errno=%d)",
              apk.last_error().c_str(), apk.last_errno());
        return nullptr;
    }

    zip::CentralDirInfo cdi;
    if (!zip::find_central_directory(apk, &cdi)) {
        RLOGE("apkEntries: no central directory found");
        return nullptr;
    }

    std::vector<std::string> flat;
    flat.reserve((size_t)cdi.total_entries * 2);
    zip::hash_all_entries(apk, cdi, [&](const zip::EntryHash& eh) {
        flat.emplace_back(eh.name);
        flat.emplace_back(eh.sha256_hex);
    });

    return strings_to_jarray(env, flat);
}

JNIEXPORT jobjectArray JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkSignerCertHashes(
        JNIEnv* env, jclass, jstring jpath) {
    if (!jpath) return nullptr;
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;

    ApkMap apk;
    bool ok = apk.open(path);
    env->ReleaseStringUTFChars(jpath, path);
    if (!ok) {
        RLOGE("apkSignerCertHashes: open failed: %s (errno=%d)",
              apk.last_error().c_str(), apk.last_errno());
        return nullptr;
    }

    zip::CentralDirInfo cdi;
    if (!zip::find_central_directory(apk, &cdi)) return nullptr;

    sigblock::SignerCerts certs;
    if (!sigblock::extract_signer_certs(apk, cdi, &certs)) {
        RLOGW("apkSignerCertHashes: no v2/v3 signing block found");
        return strings_to_jarray(env, {});
    }
    RLOGI("apkSignerCertHashes: found %zu cert(s) via %s",
          certs.cert_sha256_hex.size(),
          certs.source == sigblock::SignerCerts::Source::kV3 ? "v3" : "v2");

    return strings_to_jarray(env, certs.cert_sha256_hex);
}

JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkEntryDecompressedHash(
        JNIEnv* env, jclass, jstring jpath, jstring jentry) {
    if (!jpath || !jentry) return nullptr;

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;
    const char* entry = env->GetStringUTFChars(jentry, nullptr);
    if (!entry) {
        env->ReleaseStringUTFChars(jpath, path);
        return nullptr;
    }

    ApkMap apk;
    bool ok = apk.open(path);
    env->ReleaseStringUTFChars(jpath, path);
    if (!ok) {
        RLOGE("apkEntryDecompressedHash: open failed for entry '%s'", entry);
        env->ReleaseStringUTFChars(jentry, entry);
        return nullptr;
    }

    zip::CentralDirInfo cdi;
    if (!zip::find_central_directory(apk, &cdi)) {
        env->ReleaseStringUTFChars(jentry, entry);
        return nullptr;
    }

    uint8_t md[sha::kDigestLen];
    bool found = zip::hash_entry_decompressed(apk, cdi, entry, md);
    env->ReleaseStringUTFChars(jentry, entry);
    if (!found) return nullptr;

    return make_jstring(env, hex::encode(md, sha::kDigestLen));
}

} // extern "C"

} // namespace dicore
