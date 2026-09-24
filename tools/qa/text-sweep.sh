#!/bin/bash
# Text-only sed sweep over tracked files.
#
# Binary detection is a real NUL-byte test. Two traps this deliberately avoids:
#
#  1. `file --mime ... charset=binary` is a GUESS. Several Kotlin sources embed a
#     literal 0x1f (the FS separator in the token binding format), which makes
#     `file` call them binary. During the tech.thessemaj.deviceintelligence rename that silently
#     skipped FrameworkShim.kt, the most identifier-dense file in the project.
#
#  2. `grep -q $'\x00'` does NOT test for NUL. Bash strings cannot hold a NUL, so
#     $'\x00' expands to the EMPTY string and the grep matches every file — a
#     guard written that way skips everything and reports success.
#
# `tr -d '\000' | cmp -s` compares the file against itself with NULs removed:
# identical means there were none, i.e. it is text.
#
# Usage: tools/qa/text-sweep.sh -e 's/old/new/g' [-e ...]
set -uo pipefail
git ls-files -z | while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  if LC_ALL=C tr -d '\000' < "$f" | cmp -s - "$f"; then printf '%s\0' "$f"; fi
done | xargs -0 -r sed -i "$@"
