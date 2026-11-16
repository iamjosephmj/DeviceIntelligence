#!/usr/bin/env bash
# Build the docs site locally: ~/.venvs/mkdocs/bin/mkdocs build --strict --site-dir /tmp/di-site
exec ~/.venvs/mkdocs/bin/mkdocs build --strict --site-dir "${1:-/tmp/di-site}"
