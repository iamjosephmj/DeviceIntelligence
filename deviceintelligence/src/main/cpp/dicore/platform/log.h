#pragma once

#include <android/log.h>

#define DICORE_LOG_TAG "dicore"


// Logging is a LEAK vector: an attacker runs `logcat -s dicore` to watch every
// detection live, and the plaintext format strings in the .so document each
// detector. So it is compiled OUT of the shipping build. DICORE_LOG defaults to
// ON for debug/eval builds and OFF once NDEBUG is defined (release / the
// obfuscated build) — where RLOG* become no-ops, so there is no logcat output
// AND the format strings are dropped from the binary. Force it either way with
// -DDICORE_LOG=1 / 0.
//
// Invariant: log arguments must be side-effect-free (they are just reads of
// already-computed state) — when logging is off the argument expressions are
// discarded unevaluated.
#ifndef DICORE_LOG
#  ifdef NDEBUG
#    define DICORE_LOG 0
#  else
#    define DICORE_LOG 1
#  endif
#endif

#if DICORE_LOG
#  define RLOGI(...) __android_log_print(ANDROID_LOG_INFO,  DICORE_LOG_TAG, __VA_ARGS__)
#  define RLOGW(...) __android_log_print(ANDROID_LOG_WARN,  DICORE_LOG_TAG, __VA_ARGS__)
#  define RLOGE(...) __android_log_print(ANDROID_LOG_ERROR, DICORE_LOG_TAG, __VA_ARGS__)
#  define RLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, DICORE_LOG_TAG, __VA_ARGS__)
#else
// No-op that still type-checks the arguments (so log-only locals aren't
// -Wunused) but is dead-code-eliminated at -O2, and whose format strings are
// unreferenced at runtime so --gc-sections drops them from the binary.
#  define DICORE_LOG_NOP(...) \
       do { if (false) __android_log_print(ANDROID_LOG_INFO, DICORE_LOG_TAG, __VA_ARGS__); } while (0)
#  define RLOGI(...) DICORE_LOG_NOP(__VA_ARGS__)
#  define RLOGW(...) DICORE_LOG_NOP(__VA_ARGS__)
#  define RLOGE(...) DICORE_LOG_NOP(__VA_ARGS__)
#  define RLOGD(...) DICORE_LOG_NOP(__VA_ARGS__)
#endif
