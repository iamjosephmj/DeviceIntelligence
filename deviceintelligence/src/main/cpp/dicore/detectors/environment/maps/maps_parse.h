#pragma once

// /proc/self/maps line parsing and code-root classification.
//
// The mostly-pure half of the maps scan: turn a maps line into its pieces and
// decide whether a path is a legitimate code root. Split out because it is shared
// by every probe in this family that reads maps, and because it is the part that can
// be reasoned about — and tested — without a device.
//
// Every input here is attacker-influenced (a hider rewrites the very path strings we
// classify), so nothing trusts a field's shape and an unparseable line contributes
// nothing rather than a guess.

#include <cstdint>
#include <string>

namespace dicore {
namespace env {

// Reads /proc/self/maps in full. The kernel materializes the file on each read (it
// lies about size, so stat() is useless); the buffer grows geometrically. False on
// any read failure -> the caller contributes nothing.
bool read_proc_self_maps(std::string* out);

// Whole-token match: the needle must be bounded by non-[A-Za-z0-9_] on both sides,
// so "libwhale" matches "/x/libwhale.so" and "[anon:libwhale.so]" but NOT
// "/x/mylibwhalefoo/…". Raw substring matching here false-fired on ordinary paths
// containing "whale"/"dobby"/etc.
bool boundary_match(const std::string& hay, const char* needle);

// The pathname column of a maps line, or "" when the mapping is anonymous.
std::string extract_pathname(const std::string& line);

// "7ab5-7ab6" style range column -> start/end. False if it does not parse.
bool range_bounds(const std::string& range, uintptr_t* s, uintptr_t* e);

// Size in bytes of a range column, 0 when unparseable.
unsigned long long region_size(const std::string& range);

// Append an FS-delimited field to a record.
std::string append_field(std::string r, const std::string& f);

// Is this path one of the roots legitimate executable code is loaded from
// (/system, /apex, /vendor, /product, the app's own dir)? Anything else mapped
// executable is foreign, which is the whole basis of the provenance signals.
bool is_legit_code_root(const std::string& p);

// Does this anonymous mapping look like an ART/JIT code cache? Those are RWX for
// legitimate reasons, so they must not read as a hook trampoline pool.
bool jit_container(const std::string& p);
bool jit_anon(const std::string& p);

}  // namespace env
}  // namespace dicore
