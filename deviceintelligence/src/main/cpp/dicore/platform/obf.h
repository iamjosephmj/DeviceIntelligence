#pragma once

// Cold-core protection markers, resolved by the release build's compiler
// launcher (see tools/obfuscator/). No-ops under a plain toolchain.
#if defined(__aarch64__) || defined(__x86_64__)
#  define DI_OBF_MAX __attribute__((annotate("bcf sub split icall ibr igv cse")))
#else  // armeabi-v7a: reduced profile
#  define DI_OBF_MAX __attribute__((annotate("bcf sub split cse")))
#endif

// Semantic aliases — identical profile, distinct call-site intent.
#define DI_OBF_KILL   DI_OBF_MAX
#define DI_OBF_ATTEST DI_OBF_MAX
#define DI_OBF_ORCH   DI_OBF_MAX
#define DI_OBF_EMU    DI_OBF_MAX
