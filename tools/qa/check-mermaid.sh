#!/bin/bash
# Render every ```mermaid block in the repo's Markdown and fail if any won't parse.
#
# GitHub renders these client-side, so a broken diagram is invisible to every other
# check — fences stay balanced, links still resolve, the build is green, and the
# reader just gets a parse error where the picture should be. A ';' inside a `note`
# shipped to main exactly that way: mermaid treats it as a statement separator.
#
# Usage: tools/qa/check-mermaid.sh
set -uo pipefail
fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

while IFS= read -r f; do
  python3 - "$f" "$tmp" <<'PY'
import re, sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for i, m in enumerate(re.finditer(r'```mermaid\n(.*?)```', src.read_text(), re.S)):
    (out / f"{src.name}.{i}.mmd").write_text(m.group(1))
PY
done < <(git ls-files '*.md')

shopt -s nullglob
for d in "$tmp"/*.mmd; do
  if ! npx -y @mermaid-js/mermaid-cli@10 -i "$d" -o "$d.svg" >"$d.log" 2>&1; then
    echo "BROKEN: $(basename "$d")"
    grep -iE "parse error|expecting" "$d.log" | head -3
    fail=1
  else
    echo "ok: $(basename "$d")"
  fi
done
[ "$fail" -eq 0 ] && echo "ALL MERMAID DIAGRAMS RENDER" || echo "SOME DIAGRAMS FAILED TO RENDER"
exit $fail
