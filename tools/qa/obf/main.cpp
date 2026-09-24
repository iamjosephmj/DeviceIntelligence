// Roundtrip leg of the obfuscation artifact check (tools/qa/obf-check.sh).
// Plays the role of the JNI runtime: receives the registration tables the
// registrar hands to the opaque indirect call and verifies every string the
// pass encrypted matches its expected plaintext — i.e. the pass-emitted
// load-time decryptor (dicore.strdec ctor) restored the data exactly.
// The expected literals live in THIS translation unit (compiled separately),
// so they never appear in the fixture object that the `strings` leg inspects.
#include <cstdio>
#include <cstring>

struct JniMethod { const char* name; const char* sig; void* fn; };
struct InlineMethod { char name[32]; char sig[64]; void* fn; };

static const JniMethod* g_m;
static const InlineMethod* g_im;
static const char* g_cls;

static int fake_install(const JniMethod* m, int, const InlineMethod* im, int, const char* cls) {
    g_m = m;
    g_im = im;
    g_cls = cls;
    return 0;
}

extern "C" int dicoreobfmark_register(
        int (*install)(const JniMethod*, int, const InlineMethod*, int, const char*));

static int fails = 0;

static void expect(const char* what, const char* got, const char* want) {
    if (!got || strcmp(got, want) != 0) {
        printf("MISMATCH %s: got=%s want=%s\n", what, got ? got : "(null)", want);
        ++fails;
    }
}

int main() {
    if (dicoreobfmark_register(&fake_install) != 0 || !g_m || !g_im || !g_cls) {
        puts("OBF-ROUNDTRIP FAIL (install not reached)");
        return 1;
    }
    expect("class path", g_cls, "DICOREOBFMARK_CLASS_com/dicoreobf/mark/K");
    expect("ptr name r", g_m[0].name, "DICOREOBFMARK_PTR_NAME_r");
    expect("ptr sig r", g_m[0].sig, "()Z");
    expect("ptr name q7", g_m[1].name, "q7");
    expect("ptr sig q7", g_m[1].sig, "(I)I");
    expect("ptr name g", g_m[2].name, "DICOREOBFMARK_PTR_NAME_g");
    expect("ptr sig g", g_m[2].sig, "(Ljava/lang/String;)Ljava/lang/String;");
    expect("inl name a", g_im[0].name, "DICOREOBFMARK_INL_NAME_a");
    expect("inl sig a", g_im[0].sig, "()Z");
    expect("inl name b", g_im[1].name, "DICOREOBFMARK_INL_NAME_b");
    expect("inl sig b", g_im[1].sig, "(Ljava/lang/String;)Ljava/lang/String;");
    if (fails) {
        puts("OBF-ROUNDTRIP FAIL");
        return 1;
    }
    puts("OBF-ROUNDTRIP OK");
    return 0;
}
