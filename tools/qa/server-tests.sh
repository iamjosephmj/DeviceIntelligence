#!/usr/bin/env bash
# Host tests for the Python reference backend (tools/server/verify_token.py).
#
# The oracle is the same fp-e2e capture the Kotlin FingerprintE2ETest runs through
# ScanVerifier, so the two implementations are held to one ground truth. Exit
# non-zero if any test fails — CI-friendly.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../server/test_verify_token.py"
