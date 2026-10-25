#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" repo
cd repo
blob=$(printf 'contents\n' | git hash-object -w --stdin)
printf '100644 %s\ttracked-\377\0' "$blob" | git update-index -z --index-info
git commit -m initial
printf 'untracked\n' >untracked
printf 'other\n' >other
