#pragma once

// Reading arm64 trampoline stubs: given an RWX region, where do its stubs actually
// branch to?
//
// This is the discriminator that stops the RWX signal being useless. An RWX page on
// its own is ambiguous — an ART JIT cache is RWX too — so each region is
// characterized by its CONTENTS: a stub branching into real system code (or into a
// foreign module) is a hook redirecting execution; a self-referential or empty region
// is a cache. Without this, RWX is a false-positive cannon; with it, it is evidence.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace dicore {
namespace env {

// Classify where the stubs in [alo,ahi) branch, given the foreign executable ranges
// [fr] and their module ids [fmod]: "self" (intra-region — a JIT cache), "legit"
// (into system libc/libart — a hook over real code), "foreign[:module_id]" (into an
// injected module), "other"/"none". [out_found] reports whether any stub resolved.
std::string trampoline_target(uintptr_t alo, uintptr_t ahi,
                              const std::vector<std::pair<uintptr_t, uintptr_t>>& fr,
                              const std::vector<std::string>& fmod,
                              bool* out_found = nullptr);

// Decode an absolute-branch prologue at [addr] and return its target, 0 if it is not
// one. Bounds-checked: the bytes are attacker-written by definition.
uintptr_t prologue_branch_target(uintptr_t addr);

// Follow a branch chain from [start] (bounded hop count) to where it lands, and
// report its class in [out_class].
std::string trampoline_follow(uintptr_t start,
                              const std::vector<std::pair<uintptr_t, uintptr_t>>& fr,
                              const std::vector<std::string>& fmod,
                              std::string* out_class);

}  // namespace env
}  // namespace dicore
