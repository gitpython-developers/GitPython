#!/usr/bin/env bash
set -eu
git init -q --object-format="$1" --ref-format="$2" repo
cd repo
printf initial > tracked
git add tracked
git commit -qm initial
oid=$(git rev-parse HEAD:tracked)
for stage in 1 2 3; do
    printf '100644 %s %s\tconflict\n' "$oid" "$stage"
done | git update-index --index-info
printf changed > tracked
