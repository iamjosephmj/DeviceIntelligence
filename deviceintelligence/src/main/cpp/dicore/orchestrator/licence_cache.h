#pragma once

#include <string>

namespace dicore {

// Outcome of ONE licence evaluation.
//
// The third state is the point of this file. The licence check reads two values
// through the framework shim (the licence asset and the package name), and the
// shim is null until NativeBridge.s() registers it. An evaluation that ran before that
// bootstrap read "" for both and concluded "package mismatch" — a rejection
// manufactured from an input that was never available. Cached in a magic static,
// that rejection was permanent: initialize() returned false for the rest of the
// process no matter how many times it was called.
//
// DEFERRED says "no verdict yet, ask again" and is deliberately not cacheable, so
// the answer is settled by the first evaluation that had something to judge. This
// is the same fail-open convention every detector follows: an input we cannot
// read contributes nothing, rather than contributing a guess.
enum class LicenceEval {
    VALID,     // parsed, in date, and either unbound or bound to this package
    INVALID,   // conclusive rejection, judged against inputs we actually read
    DEFERRED,  // the framework shim was not up; nothing was judged
};

// Everything one evaluation needs from the framework, lifted out so the policy is
// pure and host-testable. `pkg_matches` is only meaningful when `pkg_readable`.
struct LicenceInputs {
    bool asset_readable;  // fw_licence_asset() returned bytes
    bool parsed;          // licence_blob_parse() accepted those bytes
    bool bound;           // the blob carries a non-zero pkg_hash
    bool pkg_readable;    // fw_package_name() returned a non-empty name
    bool pkg_matches;     // sha256(package) == pkg_hash
    bool expired;         // not_after != 0 && now > not_after
};

// WHY a licence was rejected, for the degraded token's attestation block: the
// backend has to tell an expired blob (which has a benign cause — see the bug-vs-
// injection split in the degraded-token design) apart from one bound to another
// package. OK covers both "accepted" and "not judged yet".
enum class LicenceReason {
    OK,
    EXPIRED,
    PKG_MISMATCH,
    UNPARSEABLE,   // no readable asset, or bytes that are not a licence blob
};

// Whether /proc/self/cmdline has been renamed from its fork-time value to the
// app's package.
//
// A forked app process is still "zygote64" until ActivityThread renames it — a name
// that is NON-EMPTY and WRONG, so hashing it produced a conclusive package mismatch
// that was then cached for the life of the process. Anything running at fork time
// (an Xposed framework loading modules, say) could latch the process into a
// permanent "unlicensed" before the app's own bootstrap ran.
//
// Returning false makes the evaluation DEFERRED rather than a rejection. The list is
// the fork-time names only: a genuinely mismatched package still reads as settled,
// so this cannot be used to dodge the package binding.
bool pkg_name_is_settled(const std::string& name);

// Pure policy. See LicenceEval for why DEFERRED exists.
LicenceEval licence_evaluate(const LicenceInputs& in);

// The rejection reason for the same inputs. Reported in the evaluation order, so
// an expired blob that ALSO names another package reports EXPIRED.
LicenceReason licence_reason(const LicenceInputs& in);

// True for the two conclusive outcomes. A DEFERRED evaluation must be re-run on
// the next call, which costs one asset read and one parse until the shim is up.
bool licence_should_cache(LicenceEval e);

}  // namespace dicore
