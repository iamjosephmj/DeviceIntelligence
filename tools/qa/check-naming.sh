#!/usr/bin/env bash
# Fail if retired branding creeps back into tracked files.
#
# This exists because the tech.thessemaj.deviceintelligence rename was applied with hand-written sed
# and NOTHING verified it. tools/qa/text-sweep.sh is an APPLIER, not a checker —
# it happily applies an incomplete pattern set and reports success. Months later
# ~340 stale references were still in the tree, including an entire un-renamed
# module (corpus/red-team/lsposed-tester still shipped applicationId io.ssemaj.*) and a
# tracked duplicate MainHook.kt pointing at a class that no longer existed.
#
# The signal registry has gen-signal-ids.py --check for exactly this reason.
# Naming now has the same gate.
set -uo pipefail
cd "$(dirname "$0")/../.."

# Retired tokens. Anything matching is a regression UNLESS it is allow-listed below.
BANNED='ssemaj|deviceintelligence|device_intelligence|DeviceIntelligence|[Hh]ydra|DiObf|diobf|\bDI_OBF_|\bDI_TOKEN\b|\bDI_SESSION\b|\bdi_[a-z]|DI-[A-Z]|^name=DI |\bdiyellow\b|di\.(lsp|zdg|zygisk)\.mode'

# Deliberate, permanent exceptions — each one load-bearing:
#   FrameworkShim.kt   the FROZEN keystore aliases. Renaming them orphans every
#                      key already provisioned on every device in the field.
#   device-intelligence-lab / github URLs  the actual repo name and real links.
#   di-token-v         appears only in comments explaining the OLD value of a
#                      crypto info string; rewriting it destroys the history.
# FrameworkShim.kt holds the AndroidKeyStore aliases, which keep the retired
# branding on purpose: an alias is the only handle to an existing key, so renaming
# one orphans every key already provisioned on a device.
#
# zygisk-downgrade/module.cpp must match that alias BYTE FOR BYTE — its suppression
# modes find the alias inside the outgoing keystore2 parcel — so it necessarily
# carries the same literal. Red-team only, never shipped.
ALLOW='deviceintelligence/src/main/kotlin/tech/thessemaj/deviceintelligence/internal/FrameworkShim.kt|tools/qa/check-naming.sh'

hits=$(git grep -InE "$BANNED" -- . \
       | grep -vE "^($ALLOW):" \
       | grep -v 'device-intelligence-lab' \
       | grep -v 'github.com/iamjosephmj/DeviceIntelligence' \
       | grep -v 'di-token-v')

if [ -n "$hits" ]; then
    echo "Retired branding found in tracked files:" >&2
    echo "$hits" >&2
    echo >&2
    echo "The project is 'deviceintelligence' (tech.thessemaj.deviceintelligence). If an occurrence is deliberate," >&2
    echo "add it to ALLOW in tools/qa/check-naming.sh with a reason." >&2
    exit 1
fi
echo "naming clean: no retired branding in tracked files"
