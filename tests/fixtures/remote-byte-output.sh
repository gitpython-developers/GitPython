#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" --ref-format=reftable source
git -C source commit --allow-empty -m initial
oid=$(git -C source rev-parse HEAD)
printf 'create refs/heads/branch-\377\0%s\0' "$oid" | git -C source update-ref --stdin -z
git init --initial-branch=main --object-format="$1" --ref-format=reftable repo
git init --bare --object-format="$1" --ref-format=reftable target
