// Host unit test for the pure licence-caching policy. Not built by gradle;
// compiled directly with host clang++ (see tools/qa/native-unit-tests.sh).
//
// The bug this pins: licence() was a magic static, so ONE evaluation made before
// the framework shim was registered (fw_package_name() == "") cached a permanent
// rejection for the life of the process — initialize() then returned false
// forever, with no way back. An answer derived from an input we could not read is
// not an answer; it must be DEFERRED and re-tried, never cached.
#include "dicore/orchestrator/licence_cache.h"

#include <cassert>
#include <cstdio>

using namespace dicore;

static LicenceInputs healthy() {
    LicenceInputs in{};
    in.asset_readable = true;
    in.parsed         = true;
    in.bound          = true;
    in.pkg_readable   = true;
    in.pkg_matches    = true;
    in.expired        = false;
    return in;
}

int main() {
    // --- conclusive VALID ---------------------------------------------------
    assert(licence_evaluate(healthy()) == LicenceEval::VALID);

    // An RVN1 blob carries no package binding: unbound is not mismatched, and the
    // package name is never read, so an absent shim cannot defer it.
    LicenceInputs unbound = healthy();
    unbound.bound = false;
    unbound.pkg_readable = false;
    unbound.pkg_matches  = false;
    assert(licence_evaluate(unbound) == LicenceEval::VALID);

    // --- conclusive INVALID -------------------------------------------------
    LicenceInputs mismatch = healthy();
    mismatch.pkg_matches = false;
    assert(licence_evaluate(mismatch) == LicenceEval::INVALID);

    LicenceInputs expired = healthy();
    expired.expired = true;
    assert(licence_evaluate(expired) == LicenceEval::INVALID);

    LicenceInputs corrupt = healthy();
    corrupt.parsed = false;
    assert(licence_evaluate(corrupt) == LicenceEval::INVALID);

    // --- DEFERRED: the shim was not up, so there was no input to judge -------
    // THE REGRESSION. Bound blob + unreadable package name == no verdict, not a
    // rejection. pkg_matches is false here only because sha256("") != pkg_hash.
    LicenceInputs noShim = healthy();
    noShim.pkg_readable = false;
    noShim.pkg_matches  = false;
    assert(licence_evaluate(noShim) == LicenceEval::DEFERRED);

    // The asset itself is read through the shim, so an unreadable asset is the
    // same "too early" condition one step further out.
    LicenceInputs noAsset = healthy();
    noAsset.asset_readable = false;
    noAsset.parsed         = false;
    assert(licence_evaluate(noAsset) == LicenceEval::DEFERRED);

    // Expiry outranks a missing shim: it needs no framework input at all, so it
    // stays conclusive even when nothing else can be read.
    LicenceInputs expiredNoShim = expired;
    expiredNoShim.pkg_readable = false;
    expiredNoShim.pkg_matches  = false;
    assert(licence_evaluate(expiredNoShim) == LicenceEval::INVALID);

    // --- the rejection reason, for the degraded token's attestation block ----
    // A degraded token must name WHY it degraded, and "expired" is a materially
    // different story from "bound to another package": one has a benign cause.
    assert(licence_reason(healthy()) == LicenceReason::OK);
    assert(licence_reason(expired) == LicenceReason::EXPIRED);
    assert(licence_reason(mismatch) == LicenceReason::PKG_MISMATCH);
    assert(licence_reason(corrupt) == LicenceReason::UNPARSEABLE);
    assert(licence_reason(noShim) == LicenceReason::OK);       // deferred, not rejected
    assert(licence_reason(noAsset) == LicenceReason::UNPARSEABLE);
    assert(licence_reason(unbound) == LicenceReason::OK);
    // Expiry is reported ahead of a mismatch, matching the evaluation order.
    LicenceInputs both = expired;
    both.pkg_matches = false;
    assert(licence_reason(both) == LicenceReason::EXPIRED);

    // --- the process is not named yet ---------------------------------------
    // MEASURED on the reference device: a forked app process is still called
    // "zygote64" in /proc/self/cmdline until ActivityThread renames it. That name is
    // NON-EMPTY and WRONG, so it produced sha256("zygote64") != pkg_hash — a
    // CONCLUSIVE package mismatch, cached for the life of the process. Any code that
    // runs at fork time (an Xposed framework loading its modules, for instance) could
    // therefore latch the process into a permanent "unlicensed" before the app's own
    // bootstrap ever ran. Emptiness was already handled; this is the same hole one
    // step along: a name we have, but not yet the app's.
    assert(pkg_name_is_settled("tech.thessemaj.deviceintelligence.sample"));
    assert(!pkg_name_is_settled(""));
    assert(!pkg_name_is_settled("zygote"));
    assert(!pkg_name_is_settled("zygote64"));
    assert(!pkg_name_is_settled("usap64"));
    assert(!pkg_name_is_settled("app_process"));
    assert(!pkg_name_is_settled("app_process64"));
    assert(!pkg_name_is_settled("<pre-initialized>"));
    // A real mismatch must stay conclusive — this must not become a way to dodge the
    // package binding by naming yourself something odd.
    assert(pkg_name_is_settled("com.evil.repack"));

    // --- caching policy -----------------------------------------------------
    // Both conclusive answers are cached once and never recomputed; DEFERRED is
    // never cached, which is the whole fix.
    assert(licence_should_cache(LicenceEval::VALID)    == true);
    assert(licence_should_cache(LicenceEval::INVALID)  == true);
    assert(licence_should_cache(LicenceEval::DEFERRED) == false);

    printf("all licence_cache policy tests passed\n");
    return 0;
}
