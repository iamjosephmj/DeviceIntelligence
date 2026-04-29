/*
 * F18 red-team — clean-baseline verifier.
 *
 * Loads alongside _verify_helper.js. Performs no tampering.
 * Just resets the F18 cache and prints the live findings.
 * Used in the M17 final smoke to confirm a clean process
 * reports zero F18 findings on each device.
 */

'use strict';

setImmediate(function () {
    f18VerifyAndReport('clean');
});
