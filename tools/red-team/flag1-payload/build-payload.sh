#!/usr/bin/env bash
# Build CTF Flag 1's `payload.dex`.
#
# Compiles `Payload.java` to a class file and converts it to a
# DEX via `d8`. The resulting `payload.dex` is what the Flag 1
# harness scripts (`dex-injection-inmemory.js`,
# `dex-injection-disk.js`) load into the running sample app.
#
# Idempotent: re-running overwrites the artefacts in place. Safe
# to commit `payload.dex` to the repo (a few hundred bytes, only
# regenerated when Payload.java changes).
#
# Requires:
#   - JDK with `javac` (for compiling Payload.java)
#   - Android SDK build-tools `d8` on PATH, OR ANDROID_SDK_ROOT
#     pointing at a build-tools install we can locate.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v javac >/dev/null 2>&1; then
  echo "javac not on PATH — set JAVA_HOME or install a JDK" >&2
  exit 1
fi

D8=""
if command -v d8 >/dev/null 2>&1; then
  D8="d8"
elif [ -n "${ANDROID_SDK_ROOT:-}" ]; then
  # Newest build-tools wins; fall back to whichever is found.
  D8="$(find "$ANDROID_SDK_ROOT/build-tools" -maxdepth 2 -name d8 2>/dev/null | sort -V | tail -1)"
elif [ -n "${ANDROID_HOME:-}" ]; then
  D8="$(find "$ANDROID_HOME/build-tools" -maxdepth 2 -name d8 2>/dev/null | sort -V | tail -1)"
fi

if [ -z "$D8" ]; then
  echo "could not locate d8 — set ANDROID_SDK_ROOT or put d8 on PATH" >&2
  exit 1
fi

echo "+ javac Payload.java"
javac -source 1.8 -target 1.8 -d build Payload.java

echo "+ $D8 build/Payload.class"
"$D8" --output . build/Payload.class

# d8 emits classes.dex; rename to the canonical name our harness
# expects so consumers don't need to track which name d8 picked.
mv -f classes.dex payload.dex
rm -rf build

echo "wrote $(pwd)/payload.dex ($(wc -c < payload.dex) bytes)"
