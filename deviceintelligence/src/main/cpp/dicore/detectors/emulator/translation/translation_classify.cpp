// translation_classify.cpp — pure classification for INTEL_0056
// (translated_environment). See translation_classify.h for the contract.

#include "dicore/detectors/emulator/translation/translation_classify.h"

#include <cstring>

namespace dicore {
namespace emu {
namespace {

// Process ISA family from the compile-time ABI (one of dicore's three shipped
// ABIs; anything else — a future riscv64 build, say — classifies as unknown
// and fails open).
constexpr int kProcessFamily =
#if defined(__aarch64__) || defined(__arm__)
        1;
#elif defined(__x86_64__) || defined(__i386__)
        2;
#else
        0;
#endif

// Name characters for token bounding: [A-Za-z0-9_]. Everything else — '.',
// '/', whitespace, ':' — bounds a token.
bool name_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

// Does `hay` contain `needle` as a whole name token? The bounded form is what
// keeps "/lib/mylibhoudinifoo.so" from counting as a libhoudini mapping.
bool token_match(const std::string& hay, const char* needle) {
    const size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay.size() < nlen) return false;
    size_t at = hay.find(needle, 0);
    while (at != std::string::npos) {
        const bool left_ok = (at == 0) || !name_char(hay[at - 1]);
        const size_t end = at + nlen;
        const bool right_ok = (end == hay.size()) || !name_char(hay[end]);
        if (left_ok && right_ok) return true;
        at = hay.find(needle, at + 1);
    }
    return false;
}

// The well-known ARM-translation bridges. Intel's libhoudini and Google's
// libndk_translation (shipped as libndk_translation.so / libndktranslation.so
// depending on image) are the only ones any shipping Android image uses.
bool names_known_bridge(const char* v) {
    if (!v || !v[0] || std::strcmp(v, "0") == 0) return false;
    return std::strstr(v, "houdini") != nullptr ||
           std::strstr(v, "ndk_translation") != nullptr ||
           std::strstr(v, "ndktranslation") != nullptr;
}

bool maps_known_bridge(const std::string& maps) {
    return token_match(maps, "libhoudini") ||
           token_match(maps, "libndk_translation") ||
           token_match(maps, "libndktranslation");
}

void copy_bounded(char* dst, size_t cap, const char* src) {
    if (!src) src = "";
    size_t i = 0;
    for (; src[i] && i < cap - 1; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

}  // namespace

int machine_isa_family(const char* machine) {
    if (!machine || !machine[0]) return 0;
    if (std::strcmp(machine, "aarch64") == 0) return 1;
    if (std::strncmp(machine, "arm", 3) == 0) return 1;   // armv8l / armv7l / armv6l ...
    if (std::strcmp(machine, "x86_64") == 0) return 2;
    if (machine[0] == 'i' && machine[1] >= '3' && machine[1] <= '6' &&
        std::strcmp(machine + 2, "86") == 0) {
        return 2;                                          // i386 .. i686
    }
    return 0;                                              // unknown -> fail open
}

TranslationFinding classify_translation_for(int process_family,
                                            const char* machine,
                                            const char* bridge_prop,
                                            const std::string& proc_maps) {
    TranslationFinding f;
    copy_bounded(f.machine, sizeof(f.machine), machine);
    copy_bounded(f.bridge, sizeof(f.bridge), bridge_prop);

    // Sub-fact 1 — kernel ISA vs process ABI. Both families must be known;
    // an unrecognised machine string contributes nothing (fail-open).
    const int mfam = machine_isa_family(machine);
    if (mfam != 0 && process_family != 0 && mfam != process_family) {
        f.process_translated = true;
    }

    // Sub-fact 2 — the image names a known translation bridge.
    f.bridge_named = names_known_bridge(bridge_prop);

    // Sub-fact 3 — a bridge lib is mapped into our own address space. This is
    // the sub-fact that survives a prop spoofer: the lib is either mapped or
    // it is not, and the maps blob is read by raw syscall.
    f.bridge_mapped = !proc_maps.empty() && maps_known_bridge(proc_maps);

    f.affirmative = f.process_translated || f.bridge_named || f.bridge_mapped;
    return f;
}

TranslationFinding classify_translation(const char* machine,
                                        const char* bridge_prop,
                                        const std::string& proc_maps) {
    return classify_translation_for(kProcessFamily, machine, bridge_prop, proc_maps);
}

}  // namespace emu
}  // namespace dicore
