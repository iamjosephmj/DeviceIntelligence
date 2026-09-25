// Artifact-test fixture for the obfuscation passes (driven by tools/qa/obf-check.sh).
// Mirrors dicore/jni/jni_register.cpp: a registrar whose native-method table
// exists in the three shapes the pass must cover —
//   (a) a local JNINativeMethod-style array of {const char*, const char*, void*}
//       whose address escapes into an opaque indirect call (RegisterNatives),
//   (b) a file-scope table carrying the same data BY VALUE as char arrays
//       (string bytes live inside the aggregate initializer, not in separate
//       string globals),
//   (c) a short (<4-byte, invisible to `strings`) method name.
// The class-path argument mirrors the FindClass string. obf-check.sh asserts
// every DICOREOBFMARK_* marker is absent from `strings` of the compiled object
// and that the pass-emitted load-time decryptor restores the exact plaintext
// (what RegisterNatives would receive) — see obf/main.cpp for the roundtrip.
#include <cstddef>

struct JniMethod { const char* name; const char* sig; void* fn; };
struct InlineMethod { char name[32]; char sig[64]; void* fn; };

// (b) file-scope table with embedded string bytes (internal linkage, like the
// registrar's __const array in the real build).
static const InlineMethod g_inline_methods[] = {
    {"DICOREOBFMARK_INL_NAME_a", "()Z", reinterpret_cast<void*>(1)},
    {"DICOREOBFMARK_INL_NAME_b", "(Ljava/lang/String;)Ljava/lang/String;",
     reinterpret_cast<void*>(2)},
};

// (d) INTEL_0042 digest-array stand-in (task A1): same IR shape as
// text_digest_probe.cpp's `static const uint8_t DICORE_TEXT_DIGEST[32]` — an
// internal-linkage ConstantDataArray the strenc pass encrypts but must NEVER
// digest-bind (the baseline has to decrypt independent of the exec digest).
// The volatile read keeps the array alive at -O2 without constant-folding it.
static const unsigned char DICORE_TEXT_DIGEST[32] = {
    'R','A','V','E','N','O','B','F','M','A','R','K','_','D','I','G','E','S','T',
    'B','A','S','E', 0,0,0,0,0,0,0,0,0};

extern "C" int dicoreobfmark_register(
        int (*install)(const JniMethod*, int, const InlineMethod*, int, const char*)) {
    if (!install) return -1;
    // keep the digest-array stand-in alive without folding it (see (d) above)
    const volatile unsigned char* dg = DICORE_TEXT_DIGEST;
    if (dg[0] == 0xff) return -2;
    // FindClass-shaped indirect call with a string literal argument.
    const char* cls = "DICOREOBFMARK_CLASS_com/dicoreobf/mark/K";
    // (a) local pointer table; (c) includes the 2-char name "q7".
    const JniMethod methods[] = {
        {"DICOREOBFMARK_PTR_NAME_r", "()Z", reinterpret_cast<void*>(10)},
        {"q7", "(I)I", reinterpret_cast<void*>(11)},
        {"DICOREOBFMARK_PTR_NAME_g", "(Ljava/lang/String;)Ljava/lang/String;",
         reinterpret_cast<void*>(12)},
    };
    return install(methods, 3, g_inline_methods, 2, cls);
}
