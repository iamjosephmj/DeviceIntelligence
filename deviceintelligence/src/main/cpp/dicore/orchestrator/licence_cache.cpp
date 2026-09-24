#include "dicore/orchestrator/licence_cache.h"

namespace dicore {

bool pkg_name_is_settled(const std::string& name) {
    if (name.empty()) return false;
    // Fork-time process names, before ActivityThread applies the package name.
    static const char* kUnnamed[] = {
        "zygote", "zygote64", "usap32", "usap64",
        "app_process", "app_process32", "app_process64", "<pre-initialized>",
    };
    for (const char* u : kUnnamed) if (name == u) return false;
    return true;
}

LicenceEval licence_evaluate(const LicenceInputs& in) {
    // Expiry first: it is decided against the blob's own not_after and the clock,
    // needs no framework input, and so stays conclusive even when the shim is
    // down. Ordering it ahead of the shim checks keeps an expired blob from being
    // re-parsed on every call for the life of the process.
    if (in.parsed && in.expired) return LicenceEval::INVALID;

    // The asset is itself read through the shim, so "no bytes" cannot be told
    // apart from "shim not up yet" — and the safe reading of an ambiguous input is
    // the one that can still be corrected. A genuinely absent asset costs one
    // empty JNI read per call and stays not-VALID; a shim that comes up later
    // resolves to the truth instead of being locked out of it.
    if (!in.asset_readable) return LicenceEval::DEFERRED;

    // Bytes we did read and could not parse is a real answer about real input.
    if (!in.parsed) return LicenceEval::INVALID;

    // RVN1 blobs carry an all-zero pkg_hash: unbound is not mismatched, there is
    // nothing to compare, and the package name is never read — so the absent shim
    // cannot defer this one.
    if (!in.bound) return LicenceEval::VALID;

    // The regression. sha256("") != pkg_hash for every real blob, so an
    // unreadable package name always looked exactly like a mismatch.
    if (!in.pkg_readable) return LicenceEval::DEFERRED;

    return in.pkg_matches ? LicenceEval::VALID : LicenceEval::INVALID;
}

LicenceReason licence_reason(const LicenceInputs& in) {
    // Same order as licence_evaluate, so the reason always explains that verdict.
    if (in.parsed && in.expired) return LicenceReason::EXPIRED;
    // An unreadable asset is DEFERRED rather than rejected, but when it is reported
    // at all the honest description of the input is that nothing parsed.
    if (!in.asset_readable) return LicenceReason::UNPARSEABLE;
    if (!in.parsed) return LicenceReason::UNPARSEABLE;
    if (!in.bound) return LicenceReason::OK;
    if (!in.pkg_readable) return LicenceReason::OK;   // deferred, not a rejection
    return in.pkg_matches ? LicenceReason::OK : LicenceReason::PKG_MISMATCH;
}

bool licence_should_cache(LicenceEval e) { return e != LicenceEval::DEFERRED; }

}  // namespace dicore
