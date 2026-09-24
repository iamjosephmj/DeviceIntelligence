#pragma once
// Minimal host stand-in for the NDK's <jni.h>, sufficient to compile
// jni_env_table.cpp on the host test toolchain (which ships no jni.h).
// The real header lays these members out inside the full 233-entry
// JNINativeInterface struct; here only the watched members exist — the
// table logic under test reads them by name, so layout is irrelevant.
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t  jboolean;
typedef int8_t   jbyte;
typedef uint16_t jchar;
typedef int16_t  jshort;
typedef int32_t  jint;
typedef int64_t  jlong;
typedef float    jfloat;
typedef double   jdouble;
typedef jint     jsize;

struct _jobject;
typedef struct _jobject* jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jobject jthrowable;
typedef jobject jweak;
typedef struct _jmethodID* jmethodID;
typedef struct _jfieldID* jfieldID;

typedef union jvalue {
    jboolean z;
    jbyte    b;
    jchar    c;
    jshort   s;
    jint     i;
    jlong    j;
    jfloat   f;
    jdouble  d;
    jobject  l;
} jvalue;

struct JNINativeInterface {
    void* GetMethodID;
    void* GetStaticMethodID;
    void* RegisterNatives;
    void* CallStaticIntMethod;
    void* CallObjectMethod;
    void* FindClass;
    void* NewObject;
    void* GetObjectClass;
    void* NewStringUTF;
    void* GetStringUTFChars;
    void* CallStaticObjectMethod;
};

struct _JNIEnv {
    const JNINativeInterface* functions;
};
typedef struct _JNIEnv JNIEnv;

#ifdef __cplusplus
}
#endif
